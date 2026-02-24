#!/usr/bin/env python3
import argparse
import json
import signal
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
    # Back-compat: prefer mach-level xpc.pretty when present.
    p = _get(ev, "xpc", "pretty", default=None)
    return isinstance(p, str) and len(p) > 0


def _has_hl_xpc(ev: Dict[str, Any]) -> bool:
    xpc = ev.get("xpc")
    if not isinstance(xpc, dict):
        return False
    # New structured representation.
    sf = xpc.get("string_fields")
    if isinstance(sf, dict):
        for v in sf.values():
            if isinstance(v, str) and v:
                return True
    # Back-compat slots.
    for k in ("str0", "str1", "str2", "str3"):
        v = xpc.get(k)
        if isinstance(v, str) and v:
            return True
    # Metadata-only high-level events (e.g. call_event_handler) should still be included.
    if isinstance(xpc.get("func_name"), str) and xpc.get("func_name"):
        return True
    if xpc.get("func") is not None:
        return True
    return False


def _has_selected_xpc(ev: Dict[str, Any], *, use_mach_pretty: bool, use_hl_strings: bool) -> bool:
    if use_mach_pretty and _has_xpc_pretty(ev):
        return True
    if use_hl_strings and _has_hl_xpc(ev):
        return True
    return False


def _xpc_hl_parts(ev: Dict[str, Any]) -> List[str]:
    xpc = ev.get("xpc")
    if not isinstance(xpc, dict):
        return []

    parts: List[str] = []
    sf = xpc.get("string_fields")
    if isinstance(sf, dict):
        for k in sorted(sf.keys()):
            v = sf.get(k)
            if not isinstance(v, str) or not v:
                continue
            if "\n" in v:
                parts.append(f"{k}:\n{v}")
            else:
                parts.append(f"{k}: {v}")
    else:
        for k in ("str0", "str1", "str2", "str3"):
            v = xpc.get(k)
            if not isinstance(v, str) or not v:
                continue
            if "\n" in v:
                parts.append(f"{k}:\n{v}")
            else:
                parts.append(f"{k}: {v}")

    args_named = xpc.get("args_named")
    if isinstance(args_named, dict):
        for k in sorted(args_named.keys()):
            v = args_named.get(k)
            if v is None:
                continue
            parts.append(f"arg.{k}: {v}")

    serialized = xpc.get("serialized")
    if isinstance(serialized, dict):
        for slot in ("message", "reply", "event"):
            ent = serialized.get(slot)
            if not isinstance(ent, dict):
                continue
            fmt = ent.get("format")
            stored_len = _as_int(ent.get("stored_len"), 0)
            original_len = _as_int(ent.get("original_len"), 0)
            trunc = bool(ent.get("truncated", False))
            hdr = f"serialized.{slot}: format={fmt} stored={stored_len} original={original_len}"
            if trunc:
                hdr += " truncated=true"
            parts.append(hdr)
            pretty = ent.get("pretty")
            if isinstance(pretty, str) and pretty:
                if "\n" in pretty:
                    parts.append(f"serialized.{slot}.pretty:\n{pretty}")
                else:
                    parts.append(f"serialized.{slot}.pretty: {pretty}")

    return parts


def _xpc_text(ev: Dict[str, Any], *, use_mach_pretty: bool, use_hl_strings: bool) -> Optional[str]:
    blocks: List[str] = []

    if use_mach_pretty:
        p = _get(ev, "xpc", "pretty", default=None)
        if isinstance(p, str) and p:
            blocks.append(p)

    if use_hl_strings:
        parts = _xpc_hl_parts(ev)
        if parts:
            blocks.append("\n".join(parts))

    if not blocks:
        return None
    return "\n\n".join(blocks)


def _is_entry_kind(kind: str) -> bool:
    return kind.startswith("entry") or kind == "xpc_entry"


def _is_exit_kind(kind: str) -> bool:
    return kind.startswith("exit") or kind == "xpc_exit"


def _choose_entry_exit(bucket: CallBucket, ev: Dict[str, Any], *, use_mach_pretty: bool, use_hl_strings: bool) -> None:
    kind = str(ev.get("kind") or "")
    if not _has_selected_xpc(ev, use_mach_pretty=use_mach_pretty, use_hl_strings=use_hl_strings):
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


def _render_event(
    ev: Optional[Dict[str, Any]],
    label: str,
    *,
    use_mach_pretty: bool,
    use_hl_strings: bool,
    extra: str = "",
) -> str:
    if not ev:
        return f"{label}: <missing>\n"
    eid = _as_int(ev.get("event_id"), 0)
    ts = str(ev.get("ts_real") or "")
    kind = str(ev.get("kind") or "")
    pid = _as_int(ev.get("pid"), 0)
    proc_name = ev.get("proc_name")
    is_send = bool(_get(ev, "mach", "is_send", default=False))
    is_recv = bool(_get(ev, "mach", "is_recv", default=False))
    remote, local = _ports(ev)
    mach_ret = _get(ev, "mach", "ret", default=None)
    xpc_ret = _get(ev, "xpc", "ret", default=None)
    ret = _fmt_ret(mach_ret if mach_ret is not None else xpc_ret)
    pretty = _xpc_text(ev, use_mach_pretty=use_mach_pretty, use_hl_strings=use_hl_strings)

    peer_role = _get(ev, "mach", "peer_role", default=None)
    peer_pid = _get(ev, "mach", "peer_pid", default=None)
    peer_name = _get(ev, "mach", "peer_name", default=None)
    if isinstance(peer_role, str) and peer_role and peer_role != "unknown":
        extra += f" peer_role={peer_role}"
    if isinstance(peer_pid, int) and peer_pid:
        extra += f" peer_pid={peer_pid}"
    if isinstance(peer_name, str) and peer_name:
        extra += f" peer_name={peer_name}"

    # High-level XPC events include useful metadata in the xpc section; surface it inline.
    xpc_func = _get(ev, "xpc", "func_name", default=None)
    if isinstance(xpc_func, str) and xpc_func:
        conn_pid = _as_int(_get(ev, "xpc", "conn_pid", default=0), 0)
        conn_name = _get(ev, "xpc", "conn_name", default=None)
        flow = _get(ev, "xpc", "flow", default=None)
        xpc_peer_role = _get(ev, "xpc", "peer_role", default=None)
        service_name = _get(ev, "xpc", "service_name", default=None)
        conn_ptr = _get(ev, "xpc", "conn_ptr", default=None)
        msg_ptr = _get(ev, "xpc", "msg_ptr", default=None)
        conn_seq = _as_int(_get(ev, "xpc", "conn_seq", default=0), 0)
        response_to_event_id = _as_int(_get(ev, "xpc", "response_to_event_id", default=0), 0)
        extra += f" func={xpc_func}"
        if isinstance(flow, str) and flow:
            extra += f" flow={flow}"
        if isinstance(xpc_peer_role, str) and xpc_peer_role and xpc_peer_role != "unknown":
            extra += f" xpc_peer_role={xpc_peer_role}"
        if isinstance(service_name, str) and service_name:
            extra += f" service={service_name}"
        if isinstance(conn_ptr, str) and conn_ptr:
            extra += f" conn_ptr={conn_ptr}"
        if isinstance(msg_ptr, str) and msg_ptr:
            extra += f" msg_ptr={msg_ptr}"
        if conn_seq:
            extra += f" conn_seq={conn_seq}"
        if response_to_event_id:
            extra += f" response_to_event_id={response_to_event_id}"
        if conn_pid:
            extra += f" conn_pid={conn_pid}"
        if isinstance(conn_name, str) and conn_name:
            extra += f" conn_name={conn_name}"

    hdr = f"{label}: event_id={eid} ts={ts}"
    if kind:
        hdr += f" kind={kind}"
    if pid:
        hdr += f" pid={pid}"
    if isinstance(proc_name, str) and proc_name:
        hdr += f" proc={proc_name}"
    if is_send or is_recv or remote or local:
        hdr += f" send={str(is_send).lower()} recv={str(is_recv).lower()} remote=0x{remote:x} local=0x{local:x}"
    hdr += f" ret={ret}{extra}\n"
    if isinstance(pretty, str) and pretty:
        return hdr + pretty.rstrip() + "\n"
    if isinstance(xpc_func, str) and xpc_func:
        return hdr + "<no decoded XPC payload text in this event>\n"
    return hdr + "<no XPC payload in this event>\n"


def main(argv: List[str]) -> int:
    ap = argparse.ArgumentParser(
        description=(
            "Print XPC request/response bodies from xniff output (schema xniff.event.v1).\n"
            "This can print either mach-level decoded XPC payloads (xpc.pretty), high-level libxpc output\n"
            "(xpc.string_fields/args_named and legacy str0..str3), or both."
        )
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
    ap.add_argument("--mach-only", action="store_true", help="Only print mach-level decoded XPC payloads (xpc.pretty).")
    ap.add_argument("--hl-only", action="store_true", help="Only print high-level libxpc fields (xpc.string_fields / args_named).")
    ap.add_argument("--min-call-id", type=int, default=None, help="Only include call_id >= N")
    ap.add_argument("--max-call-id", type=int, default=None, help="Only include call_id <= N")
    args = ap.parse_args(argv)

    if args.mach_only and args.hl_only:
        print("error: --mach-only and --hl-only are mutually exclusive", file=sys.stderr)
        return 2
    use_mach_pretty = not args.hl_only
    use_hl_strings = not args.mach_only

    buckets: Dict[int, CallBucket] = {}
    total = 0
    total_with_xpc = 0
    recv_xpc_exits: List[Dict[str, Any]] = []
    events_by_id: Dict[int, Dict[str, Any]] = {}

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
        if _has_selected_xpc(ev, use_mach_pretty=use_mach_pretty, use_hl_strings=use_hl_strings):
            total_with_xpc += 1
            eid = _as_int(ev.get("event_id"), 0)
            if eid:
                events_by_id[eid] = ev
            _choose_entry_exit(b, ev, use_mach_pretty=use_mach_pretty, use_hl_strings=use_hl_strings)
            kind = str(ev.get("kind") or "")
            if _is_exit_kind(kind) and bool(_get(ev, "mach", "is_recv", default=False)):
                recv_xpc_exits.append(ev)

    if not buckets:
        print("No xniff.event.v1 events found.", file=sys.stderr)
        print("Tip: capture with: xniff-cli listen <pid> --jsonl", file=sys.stderr)
        return 2
    if total_with_xpc == 0:
        print("No XPC-bearing events found in this capture.", file=sys.stderr)
        if args.mach_only:
            print("Tip: you used --mach-only; ensure you didn't capture with --no-xpc, or try --hl-only.", file=sys.stderr)
        elif args.hl_only:
            print("Tip: you used --hl-only; ensure high-level libxpc hooks are installed in the target.", file=sys.stderr)
        else:
            print("Tip: for mach-level decoding, don't use --no-xpc; for high-level, try --hl-only.", file=sys.stderr)
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

        if entry is None and exit_ev is None and not b.other_xpc:
            continue

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
            sys.stdout.write(
                _render_event(entry, "REQUEST", use_mach_pretty=use_mach_pretty, use_hl_strings=use_hl_strings)
            )
            sys.stdout.write(
                _render_event(
                    exit_ev,
                    "RESPONSE",
                    use_mach_pretty=use_mach_pretty,
                    use_hl_strings=use_hl_strings,
                    extra=paired_from,
                )
            )
        else:
            if args.only_pairs:
                continue
            sys.stdout.write(_render_event(entry, "ENTRY", use_mach_pretty=use_mach_pretty, use_hl_strings=use_hl_strings))
            sys.stdout.write(
                _render_event(
                    exit_ev,
                    "EXIT",
                    use_mach_pretty=use_mach_pretty,
                    use_hl_strings=use_hl_strings,
                    extra=paired_from,
                )
            )

        if args.all and b.other_xpc:
            for ev in b.other_xpc:
                sys.stdout.write(_render_event(ev, "OTHER", use_mach_pretty=use_mach_pretty, use_hl_strings=use_hl_strings))

        # Show high-level response linkage when present: send event responded to a prior recv event.
        src = entry if entry is not None else exit_ev
        response_to_event_id = _as_int(_get(src or {}, "xpc", "response_to_event_id", default=0), 0)
        if response_to_event_id:
            linked = events_by_id.get(response_to_event_id)
            if isinstance(linked, dict):
                linked_call = _as_int(linked.get("call_id"), 0)
                linked_func = _get(linked, "xpc", "func_name", default=None)
                linked_flow = _get(linked, "xpc", "flow", default=None)
                linked_pid = _as_int(linked.get("pid"), 0)
                msg = f"LINK: response_to_event_id={response_to_event_id}"
                if linked_call:
                    msg += f" linked_call_id={linked_call}"
                if linked_pid:
                    msg += f" linked_pid={linked_pid}"
                if isinstance(linked_func, str) and linked_func:
                    msg += f" linked_func={linked_func}"
                if isinstance(linked_flow, str) and linked_flow:
                    msg += f" linked_flow={linked_flow}"
                print(msg)
            else:
                print(f"LINK: response_to_event_id={response_to_event_id} (event not found in input)")
        print()

    print(f"read_events={total} xpc_events={total_with_xpc} calls={len(buckets)}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    # Allow piping to tools like `head` without noisy BrokenPipeError traces.
    try:
        signal.signal(signal.SIGPIPE, signal.SIG_DFL)
    except Exception:
        pass
    try:
        raise SystemExit(main(sys.argv[1:]))
    except BrokenPipeError:
        raise SystemExit(0)
