#!/usr/bin/env python3
import argparse
import json
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple


def _first_non_ws_char(path: str) -> str:
    with open(path, "rb") as f:
        while True:
            b = f.read(4096)
            if not b:
                return ""
            for ch in b:
                c = chr(ch)
                if not c.isspace():
                    return c


def iter_events(path: str) -> Iterable[Dict[str, Any]]:
    first = _first_non_ws_char(path)
    if first == "[":
        with open(path, "r", encoding="utf-8") as f:
            obj = json.load(f)
        if isinstance(obj, list):
            for ev in obj:
                if isinstance(ev, dict):
                    yield ev
        return

    # Default: JSON Lines
    with open(path, "r", encoding="utf-8") as f:
        for line_no, line in enumerate(f, 1):
            s = line.strip()
            if not s:
                continue
            try:
                ev = json.loads(s)
            except json.JSONDecodeError:
                # If it's not JSONL, try whole-file JSON object/array as a fallback.
                if line_no == 1:
                    f.seek(0)
                    obj = json.load(f)
                    if isinstance(obj, list):
                        for e in obj:
                            if isinstance(e, dict):
                                yield e
                    elif isinstance(obj, dict):
                        yield obj
                return
            if isinstance(ev, dict):
                yield ev


def _get(d: Dict[str, Any], *keys: str, default: Any = None) -> Any:
    cur: Any = d
    for k in keys:
        if not isinstance(cur, dict):
            return default
        cur = cur.get(k)
    return cur if cur is not None else default


def _as_int(v: Any, default: int = 0) -> int:
    if isinstance(v, bool):
        return int(v)
    if isinstance(v, int):
        return v
    if isinstance(v, str):
        try:
            if v.startswith("0x") or v.startswith("0X"):
                return int(v, 16)
            return int(v)
        except ValueError:
            return default
    return default


def _as_float(v: Any, default: float = 0.0) -> float:
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        try:
            return float(v)
        except ValueError:
            return default
    return default


def _fmt_ret(v: Any) -> str:
    iv = _as_int(v, 0)
    return f"0x{iv:x}"


@dataclass
class CallBucket:
    call_id: int
    first_event_id: int = 1 << 60
    pid: Optional[int] = None
    tid_low: Optional[int] = None
    api: Optional[int] = None
    entry_xpc: Optional[Dict[str, Any]] = None
    exit_xpc: Optional[Dict[str, Any]] = None
    other_xpc: List[Dict[str, Any]] = field(default_factory=list)

    def note_event(self, ev: Dict[str, Any]) -> None:
        eid = _as_int(ev.get("event_id"), 1 << 60)
        if eid < self.first_event_id:
            self.first_event_id = eid
        if self.pid is None:
            self.pid = _as_int(ev.get("pid"), 0)
        if self.tid_low is None:
            self.tid_low = _as_int(ev.get("tid_low"), 0)
        if self.api is None:
            self.api = _as_int(_get(ev, "mach", "api", default=0), 0)


def _has_xpc_pretty(ev: Dict[str, Any]) -> bool:
    p = _get(ev, "xpc", "pretty", default=None)
    return isinstance(p, str) and len(p) > 0


def _is_entry_kind(kind: str) -> bool:
    return kind.startswith("entry")


def _is_exit_kind(kind: str) -> bool:
    return kind.startswith("exit")


def _choose_entry_exit(bucket: CallBucket, ev: Dict[str, Any]) -> None:
    kind = str(ev.get("kind") or "")
    if not _has_xpc_pretty(ev):
        return
    if _is_entry_kind(kind) and bucket.entry_xpc is None:
        bucket.entry_xpc = ev
        return
    if _is_exit_kind(kind) and bucket.exit_xpc is None:
        bucket.exit_xpc = ev
        return
    bucket.other_xpc.append(ev)


def _mono(ev: Dict[str, Any]) -> float:
    return _as_float(ev.get("ts_mono_s"), 0.0)


def _ports(ev: Dict[str, Any]) -> Tuple[int, int]:
    remote = _as_int(_get(ev, "mach", "remote", default=0), 0)
    local = _as_int(_get(ev, "mach", "local", default=0), 0)
    return remote, local


def _render_event(ev: Optional[Dict[str, Any]], label: str, extra: str = "") -> str:
    if not ev:
        return f"{label}: <missing>\n"
    eid = _as_int(ev.get("event_id"), 0)
    ts = str(ev.get("ts_real") or "")
    is_send = bool(_get(ev, "mach", "is_send", default=False))
    is_recv = bool(_get(ev, "mach", "is_recv", default=False))
    remote, local = _ports(ev)
    ret = _fmt_ret(_get(ev, "mach", "ret", default=0))
    pretty = _get(ev, "xpc", "pretty", default=None)
    hdr = (
        f"{label}: event_id={eid} ts={ts} send={str(is_send).lower()} recv={str(is_recv).lower()}"
        f" remote=0x{remote:x} local=0x{local:x} ret={ret}{extra}\n"
    )
    if isinstance(pretty, str) and pretty:
        return hdr + pretty.rstrip() + "\n"
    return hdr + "<no xpc.pretty in this event>\n"


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description="Print XPC request/response bodies from xniff --jsonl output (schema xniff.event.v1)."
    )
    ap.add_argument("events_path", help="Path to events.jsonl (or JSON array) captured from xniff-cli listen --jsonl")
    ap.add_argument("--all", action="store_true", help="Also print other XPC-bearing events not chosen as request/response")
    ap.add_argument("--no-pair", action="store_true", help="Disable reply-port pairing across call_id")
    ap.add_argument("--only-pairs", action="store_true", help="Only print when both request and response are present")
    ap.add_argument(
        "--require-entry-exit",
        action="store_true",
        help="Only print calls where both an XPC entry and an XPC exit were captured (non-missing).",
    )
    ap.add_argument("--min-call-id", type=int, default=None, help="Only include call_id >= N")
    ap.add_argument("--max-call-id", type=int, default=None, help="Only include call_id <= N")
    args = ap.parse_args(argv)

    buckets: Dict[int, CallBucket] = {}
    total = 0
    total_with_xpc = 0
    recv_xpc_exits: List[Dict[str, Any]] = []

    for ev in iter_events(args.events_path):
        total += 1
        if ev.get("schema") != "xniff.event.v1":
            continue
        call_id = ev.get("call_id")
        if not isinstance(call_id, int):
            continue
        if args.min_call_id is not None and call_id < args.min_call_id:
            continue
        if args.max_call_id is not None and call_id > args.max_call_id:
            continue

        b = buckets.get(call_id)
        if b is None:
            b = CallBucket(call_id=call_id)
            buckets[call_id] = b
        b.note_event(ev)
        if _has_xpc_pretty(ev):
            total_with_xpc += 1
            _choose_entry_exit(b, ev)
            kind = str(ev.get("kind") or "")
            if _is_exit_kind(kind) and bool(_get(ev, "mach", "is_recv", default=False)):
                recv_xpc_exits.append(ev)

    if not buckets:
        print("No xniff.event.v1 events found.", file=sys.stderr)
        print("Tip: capture with: xniff-cli listen <pid> --jsonl (and don't pass --no-xpc).", file=sys.stderr)
        return 2

    ordered: List[Tuple[int, CallBucket]] = sorted(buckets.items(), key=lambda kv: (kv[1].first_event_id, kv[0]))

    # Pair send-only requests with later recv replies by reply port (local port on send == local port on recv).
    # This is needed because many XPC interactions are "send mach_msg" followed by a separate "recv mach_msg".
    if (not args.no_pair) and recv_xpc_exits:
        # Build per-(pid, reply_port) FIFO queues of recv exits.
        recv_by_key: Dict[Tuple[int, int], List[Dict[str, Any]]] = {}
        for ev in recv_xpc_exits:
            pid = _as_int(ev.get("pid"), 0)
            _, local = _ports(ev)
            if pid and local:
                recv_by_key.setdefault((pid, local), []).append(ev)
        for q in recv_by_key.values():
            q.sort(key=_mono)

        def pop_next_after(key: Tuple[int, int], t0: float) -> Optional[Dict[str, Any]]:
            q = recv_by_key.get(key)
            if not q:
                return None
            # Drop any replies that are earlier than the request time.
            i = 0
            while i < len(q) and _mono(q[i]) < t0:
                i += 1
            if i >= len(q):
                return None
            ev = q.pop(i)
            return ev

        for _, b in ordered:
            if b.entry_xpc is None:
                continue
            # If this call already includes a recv, treat it as self-contained.
            entry = b.entry_xpc
            if bool(_get(entry, "mach", "is_recv", default=False)):
                continue
            if b.exit_xpc is not None and bool(_get(b.exit_xpc, "mach", "is_recv", default=False)):
                continue
            if not bool(_get(entry, "mach", "is_send", default=False)):
                continue

            pid = _as_int(entry.get("pid"), 0)
            _, reply_port = _ports(entry)
            if not pid or not reply_port:
                continue
            t0 = _mono(entry)

            paired = pop_next_after((pid, reply_port), t0)
            if paired is not None:
                b.exit_xpc = paired

    for _, b in ordered:
        api = b.api if b.api is not None else 0
        pid = b.pid if b.pid is not None else 0
        tid = b.tid_low if b.tid_low is not None else 0
        entry = b.entry_xpc
        exit_ev = b.exit_xpc

        if args.require_entry_exit and (entry is None or exit_ev is None):
            continue

        print(f"=== call_id={b.call_id} pid={pid} tid_low={tid} api={api} ===")

        entry_send = bool(_get(entry or {}, "mach", "is_send", default=False))
        entry_recv = bool(_get(entry or {}, "mach", "is_recv", default=False))
        exit_send = bool(_get(exit_ev or {}, "mach", "is_send", default=False))
        exit_recv = bool(_get(exit_ev or {}, "mach", "is_recv", default=False))

        paired_from = ""
        if exit_ev is not None and isinstance(exit_ev.get("call_id"), int) and exit_ev.get("call_id") != b.call_id:
            paired_from = f" paired_call_id={exit_ev.get('call_id')}"

        # Only call it a RESPONSE when a receive actually happens (possibly paired from a later call_id).
        if entry_send and (entry_recv or exit_recv):
            if args.only_pairs and (entry is None or exit_ev is None):
                continue
            sys.stdout.write(_render_event(entry, "REQUEST"))
            sys.stdout.write(_render_event(exit_ev, "RESPONSE", extra=paired_from))
        else:
            if args.only_pairs:
                continue
            sys.stdout.write(_render_event(entry, "ENTRY"))
            sys.stdout.write(_render_event(exit_ev, "EXIT", extra=paired_from))

        if args.all and b.other_xpc:
            for ev in b.other_xpc:
                sys.stdout.write(_render_event(ev, "OTHER"))
        print()

    print(f"read_events={total} xpc_events={total_with_xpc} calls={len(buckets)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
