#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import os
import pwd
import random
import signal
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Tuple


@dataclass
class SnifferProc:
    pid: int
    proc: subprocess.Popen
    jsonl_path: Path
    err_path: Path


@dataclass
class WorkerProc:
    worker_id: int
    pid: int
    proc: subprocess.Popen
    out_path: Path
    err_path: Path


def eprint(msg: str) -> None:
    print(msg, file=sys.stderr)


def run_cmd(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=check, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)


def write_launchd_plist(
    plist_path: Path,
    label: str,
    service: str,
    stress_bin: Path,
    server_out: Path,
    server_err: Path,
) -> None:
    plist = f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>{label}</string>
  <key>ProgramArguments</key>
  <array>
    <string>{stress_bin}</string>
    <string>--server</string>
    <string>{service}</string>
  </array>
  <key>MachServices</key>
  <dict>
    <key>{service}</key><true/>
  </dict>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>StandardOutPath</key><string>{server_out}</string>
  <key>StandardErrorPath</key><string>{server_err}</string>
</dict>
</plist>
"""
    plist_path.write_text(plist, encoding="utf-8")


def launchctl_domain_candidates() -> List[str]:
    # If running with sudo, prefer the invoking GUI user; fall back to current uid.
    out: List[str] = []
    sudo_uid = os.environ.get("SUDO_UID")
    if sudo_uid and sudo_uid.isdigit():
        out.append(f"gui/{int(sudo_uid)}")
    out.append(f"gui/{os.getuid()}")
    dedup: List[str] = []
    for d in out:
        if d not in dedup:
            dedup.append(d)
    return dedup


def domain_uid(domain: str) -> int | None:
    if not domain.startswith("gui/"):
        return None
    try:
        return int(domain.split("/", 1)[1])
    except (ValueError, IndexError):
        return None


def make_drop_privileges_preexec(target_uid: int, target_gid: int):
    def _preexec() -> None:
        try:
            os.setgroups([])
        except Exception:
            pass
        os.setgid(target_gid)
        os.setuid(target_uid)

    return _preexec


def build_if_requested(build_dir: Path, jobs: int, enabled: bool) -> None:
    if not enabled:
        return
    eprint("building targets...")
    subprocess.run(["cmake", "--build", str(build_dir), "-j", str(jobs)], check=True)


def wait_for_sniffers_ready(sniffers: List[SnifferProc], timeout_s: float = 12.0) -> Tuple[int, int]:
    deadline = time.time() + timeout_s
    ready: Dict[int, bool] = {s.pid: False for s in sniffers}
    failed = 0
    while time.time() < deadline:
        all_done = True
        for s in sniffers:
            if ready[s.pid]:
                continue
            all_done = False
            text = ""
            if s.err_path.exists():
                try:
                    text = s.err_path.read_text(encoding="utf-8", errors="replace")
                except OSError:
                    text = ""
            if "hooks installed; streaming events" in text:
                ready[s.pid] = True
                continue
            if any(tok in text for tok in ("hook-xpc failed", "failed to inject", "task_for_pid failed", "listen: failed")):
                ready[s.pid] = True
                failed += 1
                continue
            if s.proc.poll() is not None:
                ready[s.pid] = True
                failed += 1
        if all_done or all(ready.values()):
            break
        time.sleep(0.1)
    ready_count = sum(1 for v in ready.values() if v)
    return ready_count, failed


def stop_sniffers(sniffers: List[SnifferProc]) -> None:
    for s in sniffers:
        if s.proc.poll() is None:
            s.proc.terminate()
    deadline = time.time() + 1.5
    while time.time() < deadline:
        if all(s.proc.poll() is not None for s in sniffers):
            break
        time.sleep(0.05)
    for s in sniffers:
        if s.proc.poll() is None:
            s.proc.kill()


def summarize_events(sniffers: List[SnifferProc]) -> Dict[str, object]:
    total_events = 0
    parse_errors = 0
    unique_calls = set()
    kinds: Counter[str] = Counter()
    funcs: Counter[str] = Counter()
    per_pid: Dict[int, int] = {}
    per_pid_kinds: Dict[int, Counter[str]] = {}
    per_pid_xpc_entry_funcs: Dict[int, Counter[str]] = {}

    for s in sniffers:
        cnt = 0
        if s.jsonl_path.exists():
            with s.jsonl_path.open("r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    cnt += 1
                    total_events += 1
                    try:
                        evt = json.loads(line)
                    except json.JSONDecodeError:
                        parse_errors += 1
                        continue
                    kind = evt.get("kind")
                    if isinstance(kind, str):
                        kinds[kind] += 1
                    evt_pid = evt.get("pid")
                    if isinstance(evt_pid, int) and isinstance(kind, str):
                        if evt_pid not in per_pid_kinds:
                            per_pid_kinds[evt_pid] = Counter()
                        per_pid_kinds[evt_pid][kind] += 1
                    call_id = evt.get("call_id")
                    if isinstance(call_id, int) and call_id > 0:
                        unique_calls.add(call_id)
                    xpc = evt.get("xpc")
                    if isinstance(xpc, dict):
                        fn = xpc.get("func_name")
                        if isinstance(fn, str):
                            funcs[fn] += 1
                            if isinstance(evt_pid, int) and kind == "xpc_entry":
                                if evt_pid not in per_pid_xpc_entry_funcs:
                                    per_pid_xpc_entry_funcs[evt_pid] = Counter()
                                per_pid_xpc_entry_funcs[evt_pid][fn] += 1
        per_pid[s.pid] = cnt

    attach_failures = 0
    for s in sniffers:
        txt = ""
        if s.err_path.exists():
            txt = s.err_path.read_text(encoding="utf-8", errors="replace")
        if any(tok in txt for tok in ("hook-xpc failed", "failed to inject", "task_for_pid failed", "listen: failed")):
            attach_failures += 1

    return {
        "total_events": total_events,
        "parse_errors": parse_errors,
        "unique_calls": len(unique_calls),
        "kinds": kinds,
        "funcs": funcs,
        "per_pid": per_pid,
        "per_pid_kinds": per_pid_kinds,
        "per_pid_xpc_entry_funcs": per_pid_xpc_entry_funcs,
        "attach_failures": attach_failures,
    }


def parse_worker_stats(workers: List[WorkerProc]) -> Dict[int, Dict[str, int]]:
    stats_by_pid: Dict[int, Dict[str, int]] = {}
    marker = "XNIFF_STRESS_WORKER_STATS "
    for w in workers:
        for path in (w.err_path, w.out_path):
            if not path.exists():
                continue
            try:
                lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
            except OSError:
                continue
            for line in lines:
                idx = line.find(marker)
                if idx < 0:
                    continue
                raw = line[idx + len(marker) :].strip()
                try:
                    obj = json.loads(raw)
                except json.JSONDecodeError:
                    continue
                pid = obj.get("pid")
                if not isinstance(pid, int):
                    continue
                stats: Dict[str, int] = {}
                for k, v in obj.items():
                    if isinstance(v, int):
                        stats[k] = v
                stats_by_pid[pid] = stats
    return stats_by_pid


def main() -> int:
    parser = argparse.ArgumentParser(
        description="One-command xniff XPC stress harness (Python orchestrator)."
    )
    parser.add_argument("--workers", type=int, default=6)
    parser.add_argument("--threads", type=int, default=4)
    parser.add_argument("--duration", type=int, default=20, dest="duration_s")
    parser.add_argument("--min-ms", type=int, default=5)
    parser.add_argument("--max-ms", type=int, default=100)
    parser.add_argument("--sniff", type=int, default=0, help="Sniff first N workers (default: all).")
    parser.add_argument("--sniff-all", action="store_true", help="Sniff all workers.")
    parser.add_argument("--mode", choices=("mach", "xpc"), default="xpc")
    parser.add_argument("--dump", action="store_true", help="Enable /tmp/xniff/<pid> dumps.")
    parser.add_argument("--xpc", action="store_true", help="Enable XPC decoding in listener.")
    parser.add_argument("--full-capture", action="store_true")
    parser.add_argument("--hooks-debug", action="store_true")
    parser.add_argument("--late-attach", action="store_true", help="Do not gate workers before send.")
    parser.add_argument("--out", default="")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--build-jobs", type=int, default=8)
    args = parser.parse_args()

    if args.workers <= 0 or args.threads <= 0 or args.duration_s <= 0:
        parser.error("--workers/--threads/--duration must be > 0")
    if args.min_ms < 0 or args.max_ms < args.min_ms:
        parser.error("--min-ms must be >= 0 and --max-ms must be >= --min-ms")

    root = Path(__file__).resolve().parent.parent
    build_dir = root / "build"
    stress_bin = build_dir / "xniff-xpc-stress"
    xniff_cli = build_dir / "xniff-cli"
    hooks_dylib = build_dir / "libxniff-hooks.dylib"

    out_dir = Path(args.out) if args.out else Path(f"/tmp/xniff-xpc-harness-{time.strftime('%Y%m%d-%H%M%S')}")
    out_dir.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(out_dir, 0o777)
    except OSError:
        pass

    if os.geteuid() != 0:
        eprint("warn: not running as root; attach/inject may fail. Recommended: run with sudo.")

    build_if_requested(build_dir, args.build_jobs, not args.no_build)
    for p in (stress_bin, xniff_cli, hooks_dylib):
        if not p.exists():
            raise FileNotFoundError(f"missing required artifact: {p}")

    listener_flags = ["--jsonl", "--no-dump", "--no-xpc"]
    if args.dump and "--no-dump" in listener_flags:
        listener_flags.remove("--no-dump")
    if args.xpc and "--no-xpc" in listener_flags:
        listener_flags.remove("--no-xpc")

    worker_env = os.environ.copy()
    if args.hooks_debug:
        worker_env["XNIFF_HOOKS_DEBUG"] = "1"
    if not args.full_capture:
        worker_env.setdefault("XNIFF_MAX_MSG_COPY", "1024")
        worker_env.setdefault("XNIFF_MAX_OOL_TOTAL", "1")
        worker_env.setdefault("XNIFF_MAX_OOL_PER_DESC", "1")
        worker_env.setdefault("XNIFF_MAX_IPC_PAYLOAD", "131072")

    run_id = random.randint(1, 1_000_000_000)
    label = f"com.bluefalconhd.xniff.xpcstress.py.{os.getpid()}.{run_id}"
    service = f"com.bluefalconhd.xniff.xpcstress.service.py.{os.getpid()}.{run_id}"
    plist_path = Path(tempfile.gettempdir()) / f"{label}.plist"
    domains = launchctl_domain_candidates()
    server_out = out_dir / "server.out"
    server_err = out_dir / "server.err"
    write_launchd_plist(plist_path, label, service, stress_bin, server_out, server_err)

    bootstrapped = False
    active_domain = ""
    worker_procs: List[WorkerProc] = []
    sniffers: List[SnifferProc] = []
    start_t = time.time()
    early_gate = not args.late_attach
    try:
        last_err: Exception | None = None
        for domain in domains:
            try:
                eprint(f"bootstrapping launchd service in {domain} ({service})")
                subprocess.run(
                    ["/bin/launchctl", "bootstrap", domain, str(plist_path)],
                    check=True,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    text=True,
                )
                active_domain = domain
                bootstrapped = True
                break
            except subprocess.CalledProcessError as e:
                last_err = e
        if not bootstrapped:
            if last_err:
                raise last_err
            raise RuntimeError("launchctl bootstrap failed")

        worker_uid = os.geteuid()
        worker_gid = os.getegid()
        dom_uid = domain_uid(active_domain)
        if os.geteuid() == 0 and dom_uid is not None:
            worker_uid = dom_uid
            try:
                worker_gid = pwd.getpwuid(worker_uid).pw_gid
            except KeyError:
                worker_gid = int(os.environ.get("SUDO_GID", "0") or "0")

        eprint(f"worker identity: uid={worker_uid} gid={worker_gid}")

        for i in range(args.workers):
            worker_id = i + 1
            worker_out = out_dir / f"worker-{worker_id}.out"
            worker_err = out_dir / f"worker-{worker_id}.err"
            out_f = worker_out.open("w", encoding="utf-8")
            err_f = worker_err.open("w", encoding="utf-8")
            cmd = [
                str(stress_bin),
                "--worker",
                service,
                "--id",
                str(worker_id),
                "--workers",
                str(args.workers),
                "--threads",
                str(args.threads),
                "--duration",
                str(args.duration_s),
                "--min-ms",
                str(args.min_ms),
                "--max-ms",
                str(args.max_ms),
            ]
            if early_gate:
                cmd.append("--wait-signal")
            preexec = None
            if os.geteuid() == 0 and (worker_uid != 0 or worker_gid != 0):
                preexec = make_drop_privileges_preexec(worker_uid, worker_gid)
            proc = subprocess.Popen(cmd, env=worker_env, stdout=out_f, stderr=err_f, preexec_fn=preexec)
            out_f.close()
            err_f.close()
            worker_procs.append(
                WorkerProc(worker_id=worker_id, pid=proc.pid, proc=proc, out_path=worker_out, err_path=worker_err)
            )

        worker_pids = [w.pid for w in worker_procs]
        sniff_n = args.workers if (args.sniff_all or args.sniff <= 0) else min(args.sniff, args.workers)
        target_pids = worker_pids[:sniff_n]

        eprint(f"workers: {' '.join(str(p) for p in worker_pids)}")
        eprint(f"sniff targets: {sniff_n}/{len(worker_pids)} -> {out_dir}")

        for pid in target_pids:
            jsonl_path = out_dir / f"xniff-{pid}.jsonl"
            err_path = out_dir / f"xniff-{pid}.err"
            out_f = jsonl_path.open("w", encoding="utf-8")
            err_f = err_path.open("w", encoding="utf-8")
            cmd = [
                str(xniff_cli),
                "sniff-xpc",
                str(pid),
                str(hooks_dylib),
                f"--{args.mode}",
                *listener_flags,
            ]
            proc = subprocess.Popen(cmd, stdout=out_f, stderr=err_f, env=os.environ.copy())
            out_f.close()
            err_f.close()
            sniffers.append(SnifferProc(pid=pid, proc=proc, jsonl_path=jsonl_path, err_path=err_path))

        ready_count, ready_fail = wait_for_sniffers_ready(sniffers)
        eprint(f"sniffers ready={ready_count}/{len(sniffers)} failures={ready_fail}")

        if early_gate:
            for w in worker_procs:
                try:
                    os.kill(w.pid, signal.SIGUSR1)
                except ProcessLookupError:
                    pass
            eprint(f"released {len(worker_procs)} workers with SIGUSR1")

        deadline = time.time() + args.duration_s + 20
        timeout_pids = set()
        worker_rc: Dict[int, int] = {}
        for w in worker_procs:
            timeout = max(0.1, deadline - time.time())
            try:
                w.proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timeout_pids.add(w.pid)
                w.proc.terminate()
                try:
                    w.proc.wait(timeout=1.0)
                except subprocess.TimeoutExpired:
                    w.proc.kill()
                    w.proc.wait(timeout=1.0)
            worker_rc[w.pid] = w.proc.returncode if w.proc.returncode is not None else 0

        stop_sniffers(sniffers)
        summary = summarize_events(sniffers)
        worker_stats = parse_worker_stats(worker_procs)
        elapsed = int(time.time() - start_t)
        worker_crashed = sorted(pid for pid, rc in worker_rc.items() if rc < 0)
        worker_nonzero = sorted(pid for pid, rc in worker_rc.items() if rc > 0)
        worker_ok = sorted(pid for pid, rc in worker_rc.items() if rc == 0)

        print()
        print("=== xniff stress summary ===")
        print(
            f"config: workers={args.workers} threads={args.threads} duration={args.duration_s}s "
            f"mode={args.mode} early_gate={'yes' if early_gate else 'no'}"
        )
        print(f"targets: sniffed={len(sniffers)} / workers_seen={len(worker_procs)}")
        print(
            f"workers: ok={len(worker_ok)} nonzero_exit={len(worker_nonzero)} "
            f"signaled={len(worker_crashed)} timeouts={len(timeout_pids)}"
        )
        print(
            f"events: total={summary['total_events']} unique_calls={summary['unique_calls']} "
            f"parse_errors={summary['parse_errors']}"
        )
        print(f"attach_failures: {summary['attach_failures']}")
        print(f"elapsed: {elapsed}s")
        print()
        print("per-target:")
        per_pid: Dict[int, int] = summary["per_pid"]  # type: ignore[assignment]
        for pid in sorted(per_pid):
            print(f"  pid={pid} events={per_pid[pid]} file={out_dir / f'xniff-{pid}.jsonl'}")

        per_pid_xpc_entry_funcs: Dict[int, Counter[str]] = summary["per_pid_xpc_entry_funcs"]  # type: ignore[assignment]
        if worker_stats:
            print()
            print("worker reported vs observed:")
            for pid in sorted(worker_stats):
                ws = worker_stats[pid]
                sent_total = ws.get("sent_total", 0)
                sent_oneway = ws.get("sent_oneway", 0)
                sent_async = ws.get("sent_with_reply_async", 0)
                sent_sync = ws.get("sent_with_reply_sync", 0)
                recv_total = ws.get("recv_events_total", 0)
                replies_sent = ws.get("replies_sent", 0)
                peer_connections = ws.get("peer_connections", 0)
                no_peer_loops = ws.get("no_peer_loops", 0)
                observed_total = per_pid.get(pid, 0)
                observed_funcs = per_pid_xpc_entry_funcs.get(pid, Counter())
                observed_oneway = observed_funcs.get("xpc_connection_send_message", 0)
                observed_async = observed_funcs.get("xpc_connection_send_message_with_reply", 0)
                observed_sync = observed_funcs.get("xpc_connection_send_message_with_reply_sync", 0)
                observed_send_entries = observed_oneway + observed_async + observed_sync
                expected_oneway = sent_oneway + replies_sent
                expected_send_entries = expected_oneway + sent_async + sent_sync
                delta_send_entries = observed_send_entries - expected_send_entries
                delta_oneway = observed_oneway - expected_oneway
                delta_async = observed_async - sent_async
                delta_sync = observed_sync - sent_sync
                print(
                    f"  pid={pid} sent_total={sent_total} observed_events={observed_total} "
                    f"observed_xpc_send_entries={observed_send_entries} recv_events={recv_total} "
                    f"peer_connections={peer_connections} no_peer_loops={no_peer_loops}"
                )
                print(
                    f"    expected(oneway/async/sync)={expected_oneway}/{sent_async}/{sent_sync} "
                    f"observed(oneway/async/sync)={observed_oneway}/{observed_async}/{observed_sync}"
                )
                print(
                    f"    deltas(oneway/async/sync)={delta_oneway:+d}/{delta_async:+d}/{delta_sync:+d} "
                    f"send_entries_delta={delta_send_entries:+d} replies_sent={replies_sent}"
                )

        if worker_crashed or worker_nonzero or timeout_pids:
            print()
            print("worker failures:")
            for pid in worker_crashed:
                print(f"  pid={pid} crashed_by_signal={-worker_rc[pid]}")
            for pid in worker_nonzero:
                print(f"  pid={pid} exit_code={worker_rc[pid]}")
            for pid in sorted(timeout_pids):
                print(f"  pid={pid} timeout=yes")

        kinds: Counter[str] = summary["kinds"]  # type: ignore[assignment]
        if kinds:
            print()
            print("event kinds:")
            for kind, cnt in kinds.most_common():
                print(f"  {kind}: {cnt}")

        funcs: Counter[str] = summary["funcs"]  # type: ignore[assignment]
        if funcs:
            print()
            print("xpc funcs (top 8):")
            for name, cnt in funcs.most_common(8):
                print(f"  {name}: {cnt}")

        print()
        print(f"artifacts: {out_dir}")
        print(f"  stress logs: {server_out} , {server_err}")
        if worker_crashed or worker_nonzero:
            return 1
        return 0
    finally:
        stop_sniffers(sniffers)
        for w in worker_procs:
            if w.proc.poll() is None:
                w.proc.terminate()
        if bootstrapped and active_domain:
            subprocess.run(
                ["/bin/launchctl", "bootout", active_domain, str(plist_path)],
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
            )
        if plist_path.exists():
            try:
                plist_path.unlink()
            except OSError:
                pass


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except subprocess.CalledProcessError as e:
        cmd = " ".join(e.cmd) if isinstance(e.cmd, list) else str(e.cmd)
        eprint(f"error: command failed ({e.returncode}): {cmd}")
        if e.stdout:
            eprint(f"stdout:\n{e.stdout.strip()}")
        if e.stderr:
            eprint(f"stderr:\n{e.stderr.strip()}")
        raise SystemExit(1)
    except FileNotFoundError as e:
        eprint(f"error: {e}")
        raise SystemExit(1)
