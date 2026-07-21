#!/usr/bin/env python3
import argparse
import json
import re
import signal
import struct
import sys
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Tuple

from xpc_serialization import XPCDecodeError, format_xpc_serialization

XNIFF_BIN_FILE_MAGIC = 0x584E4246  # 'XNBF'
XNIFF_IPC_V2_VERSION = 1

XNIFF_DIR_ENTRY = 0
XNIFF_DIR_EXIT = 1

XNIFF_API_MACH_MSG = 1
XNIFF_API_MACH_MSG2 = 2
XNIFF_API_XPC_HL = 3
XNIFF_API_DEBUG = 4

XNIFF_XPC_FUNC_CONNECTION_CREATE = 1
XNIFF_XPC_FUNC_PIPE_ROUTINE = 2
XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE = 3
XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY = 4
XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC = 5
XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER = 6
XNIFF_XPC_FUNC_CONNECTION_CHECK_IN = 7
XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY = 8
XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE = 9
XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC = 10
XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC = 11

XNIFF_V2_SEC_MACH_HEADER_OPTIONS = 1
XNIFF_V2_SEC_MACH_INLINE_BYTES = 2
XNIFF_V2_SEC_MACH_TRAILER_BYTES = 3
XNIFF_V2_SEC_MACH_DESC_META = 4
XNIFF_V2_SEC_MACH_DESC_OOL_BYTES = 5
XNIFF_V2_SEC_MACH_DESC_PORT_ARRAY = 6
XNIFF_V2_SEC_XPC_SERIALIZED = 7
XNIFF_V2_SEC_XPC_CONN_META = 8
XNIFF_V2_SEC_HOOK_DIAG = 9
XNIFF_V2_SEC_XPC_CALL_META = 10
XNIFF_V2_SEC_BACKTRACE = 11
XNIFF_V2_SEC_BACKTRACE_SYMBOLS = 12
XNIFF_V2_SEC_CALL_ID = 13
BACKTRACE_MAX_FRAMES = 32

XNIFF_XPC_CONN_META_HAS_NAME_PUBLIC = (1 << 0)
XNIFF_XPC_CONN_META_HAS_PID_PUBLIC = (1 << 2)

MACH_SEND_MSG = 0x1
MACH_RCV_MSG = 0x2

ENTRY_HDR_FMT = "<IHHQ"
FIXED_HDR_FMT = "<IIQHHI"
SEC_HDR_FMT = "<HHI"
MACH_PL_FMT = "<6I3Q2IQ8Q"
XPC_PL_FMT = "<IIIIQ8QIIII"
XPC_SERIAL_FMT = "<BBHII"
XPC_CONN_META_FMT = "<II8I6Q8II"
DESC_META_FMT = "<IHHQIIIIII"
MACH_MSG_HDR_FMT = "<IIIIIi"
DIAG_FMT = "<II"
BACKTRACE_HDR_FMT = "<II"
BACKTRACE_SYMS_HDR_FMT = "<II"
BACKTRACE_SYM_FMT = "<QQII"


def _entry_kind(api: int, direction: int) -> str:
    if api == XNIFF_API_MACH_MSG:
        return "entry" if direction == XNIFF_DIR_ENTRY else "exit"
    if api == XNIFF_API_MACH_MSG2:
        return "entry2" if direction == XNIFF_DIR_ENTRY else "exit2"
    if api == XNIFF_API_XPC_HL:
        return "xpc_entry" if direction == XNIFF_DIR_ENTRY else "xpc_exit"
    if api == XNIFF_API_DEBUG:
        return "debug_log"
    return "unknown"


def _xpc_func_name(func: int) -> str:
    return {
        XNIFF_XPC_FUNC_CONNECTION_CREATE: "xpc_connection_create",
        XNIFF_XPC_FUNC_PIPE_ROUTINE: "xpc_pipe_routine",
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE: "xpc_connection_send_message",
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY: "xpc_connection_send_message_with_reply",
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC: "xpc_connection_send_message_with_reply_sync",
        XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER: "_xpc_connection_call_event_handler",
        XNIFF_XPC_FUNC_CONNECTION_CHECK_IN: "_xpc_connection_check_in",
        XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY: "xpc_dictionary_send_reply",
        XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE: "xpc_session_send_message",
        XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC: "xpc_session_send_message_with_reply_async",
        XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC: "xpc_session_send_message_with_reply_sync",
    }.get(func, "unknown")


def _xpc_flow(func: int) -> str:
    if func in (
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE,
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY,
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC,
        XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE,
        XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC,
        XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC,
    ):
        return "send"
    if func == XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER:
        return "recv"
    if func == XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY:
        return "reply"
    if func == XNIFF_XPC_FUNC_CONNECTION_CHECK_IN:
        return "rpc"
    if func == XNIFF_XPC_FUNC_PIPE_ROUTINE:
        return "rpc"
    if func == XNIFF_XPC_FUNC_CONNECTION_CREATE:
        return "meta"
    return "unknown"


def _xpc_role(func: int, direction: int) -> str:
    if func in (
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY,
        XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC,
    ):
        return "request" if direction == XNIFF_DIR_ENTRY else "response"
    if func in (
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC,
        XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC,
        XNIFF_XPC_FUNC_PIPE_ROUTINE,
    ):
        return "request" if direction == XNIFF_DIR_ENTRY else "response"
    if func == XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY:
        return "response"
    if func == XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER:
        return "incoming"
    if func in (XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE, XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE):
        return "one-way"
    return "metadata"


def _xpc_peer_role(flow: str) -> str:
    if flow == "send":
        return "recipient"
    if flow == "recv":
        return "sender"
    if flow == "reply":
        return "requester"
    return "unknown"


def _xpc_arg_name(func: int, idx: int) -> Optional[str]:
    table: Dict[int, Dict[int, str]] = {
        XNIFF_XPC_FUNC_CONNECTION_CREATE: {0: "service_name_ptr", 1: "target_queue_ptr"},
        XNIFF_XPC_FUNC_PIPE_ROUTINE: {0: "pipe_ptr", 1: "request_ptr_ptr", 2: "reply_ptr_ptr"},
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE: {0: "connection_ptr", 1: "message_ptr"},
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY: {
            0: "connection_ptr",
            1: "message_ptr",
            2: "reply_queue_ptr",
            3: "reply_handler_ptr",
        },
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC: {0: "connection_ptr", 1: "message_ptr"},
        XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER: {0: "connection_ptr", 1: "event_ptr"},
        XNIFF_XPC_FUNC_CONNECTION_CHECK_IN: {0: "connection_ptr"},
        XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY: {0: "reply_ptr"},
        XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE: {0: "session_ptr", 1: "message_ptr"},
        XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC: {
            0: "session_ptr", 1: "message_ptr", 2: "reply_handler_ptr"
        },
        XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC: {
            0: "session_ptr", 1: "message_ptr", 2: "error_out_ptr"
        },
    }
    return table.get(func, {}).get(idx)


def _xpc_string_field_names(kind: str, func: int) -> List[Optional[str]]:
    names: List[Optional[str]] = [None, None, None, None]
    if func == XNIFF_XPC_FUNC_CONNECTION_CREATE:
        if kind == "xpc_entry":
            names[0] = "target_service_name"
        else:
            names[0] = "connection_name"
    elif func == XNIFF_XPC_FUNC_PIPE_ROUTINE:
        names[0] = "pipe_description"
        names[1] = "request_description"
        if kind == "xpc_exit":
            names[2] = "reply_description"
    elif func in (
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE,
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY,
        XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC,
    ):
        names[0] = "connection_name"
        names[1] = "message_description"
        names[2] = "connection_description"
        if kind == "xpc_exit":
            names[3] = "reply_description"
    elif func == XNIFF_XPC_FUNC_CONNECTION_CHECK_IN:
        names[0] = "connection_name"
    return names


def _xpc_slot_name(slot: int) -> str:
    return {1: "message", 2: "reply", 3: "event"}.get(slot, f"slot_{slot}")


def _xpc_format_name(fmt: int) -> str:
    return {1: "libxpc_v5"}.get(fmt, str(fmt))


def _decode_text(b: bytes) -> str:
    return b.decode("utf-8", errors="replace")


def _looks_like_binary(path: str) -> str:
    with open(path, "rb") as f:
        head = f.read(16)
    if len(head) >= 8:
        magic = struct.unpack_from("<I", head, 0)[0]
        if magic == XNIFF_BIN_FILE_MAGIC:
            return "file"
    if len(head) >= struct.calcsize(ENTRY_HDR_FMT):
        entry_len, _etype, ver, _seq = struct.unpack_from(ENTRY_HDR_FMT, head, 0)
        min_len = struct.calcsize(ENTRY_HDR_FMT) + struct.calcsize(FIXED_HDR_FMT)
        if ver == XNIFF_IPC_V2_VERSION and min_len <= entry_len <= (64 * 1024 * 1024):
            return "raw"
    return ""


def _iter_binary_events(path: str, mode: str) -> Iterable[Dict[str, Any]]:
    entry_hdr_sz = struct.calcsize(ENTRY_HDR_FMT)
    fixed_hdr_sz = struct.calcsize(FIXED_HDR_FMT)
    sec_hdr_sz = struct.calcsize(SEC_HDR_FMT)
    mach_pl_sz = struct.calcsize(MACH_PL_FMT)
    xpc_pl_sz = struct.calcsize(XPC_PL_FMT)
    serial_sz = struct.calcsize(XPC_SERIAL_FMT)
    conn_meta_sz = struct.calcsize(XPC_CONN_META_FMT)
    mach_msg_hdr_sz = struct.calcsize(MACH_MSG_HDR_FMT)
    diag_sz = struct.calcsize(DIAG_FMT)
    backtrace_hdr_sz = struct.calcsize(BACKTRACE_HDR_FMT)
    u64_sz = struct.calcsize("<Q")
    backtrace_syms_hdr_sz = struct.calcsize(BACKTRACE_SYMS_HDR_FMT)
    backtrace_sym_sz = struct.calcsize(BACKTRACE_SYM_FMT)

    event_id = 0
    next_call_id = 1
    inflight: Dict[Tuple[int, int, int, int], List[int]] = {}
    wire_call_ids: Dict[Tuple[int, int], int] = {}

    with open(path, "rb") as f:
        if mode == "file":
            fh = f.read(8)
            if len(fh) != 8:
                return
            magic, _version, _reserved = struct.unpack("<IHH", fh)
            if magic != XNIFF_BIN_FILE_MAGIC:
                return

        while True:
            h = f.read(entry_hdr_sz)
            if not h:
                break
            if len(h) != entry_hdr_sz:
                break
            entry_len, _entry_type, ver, seq = struct.unpack(ENTRY_HDR_FMT, h)
            min_len = entry_hdr_sz + fixed_hdr_sz
            if ver != XNIFF_IPC_V2_VERSION or entry_len < min_len or entry_len > (64 * 1024 * 1024):
                break
            body_len = entry_len - entry_hdr_sz
            body = f.read(body_len)
            if len(body) != body_len:
                break

            pid, tid_low, ts_ns, direction, api, function = struct.unpack_from(FIXED_HDR_FMT, body, 0)
            kind = _entry_kind(api, direction)
            key = (pid, tid_low, api, function)
            if direction == XNIFF_DIR_ENTRY:
                call_id = next_call_id
                next_call_id += 1
                inflight.setdefault(key, []).append(call_id)
            elif direction == XNIFF_DIR_EXIT:
                q = inflight.get(key)
                if q:
                    call_id = q.pop()
                    if not q:
                        inflight.pop(key, None)
                else:
                    call_id = next_call_id
                    next_call_id += 1
            else:
                call_id = next_call_id
                next_call_id += 1

            event_id += 1
            ev: Dict[str, Any] = {
                "schema": "xniff.event.v1",
                "event_id": event_id,
                "call_id": call_id,
                "pid": pid,
                "tid_low": tid_low,
                "kind": kind,
                "ts_real": "",
                "ts_mono_s": float(ts_ns) / 1e9,
                "seq": seq,
                "mach": {"api": api},
            }

            mach_pl: Optional[Tuple[Any, ...]] = None
            inline_msg: Optional[bytes] = None
            trailer_bytes: Optional[bytes] = None
            descriptors: List[Dict[str, Any]] = []
            pending_desc: Optional[Dict[str, Any]] = None
            xpc_pl: Optional[Tuple[Any, ...]] = None
            xpc_strs: List[str] = ["", "", "", ""]
            serialized: Dict[str, Dict[str, Any]] = {}
            conn_name_public: Optional[str] = None
            conn_pid_public: int = 0
            backtrace_frames: List[int] = []
            backtrace_symbols: List[Dict[str, Any]] = []
            wire_call_id = 0

            off = fixed_hdr_sz
            while off + sec_hdr_sz <= len(body):
                sec_type, _sec_flags, sec_len = struct.unpack_from(SEC_HDR_FMT, body, off)
                off += sec_hdr_sz
                if off + sec_len > len(body):
                    break
                payload = body[off:off + sec_len]
                off += sec_len

                if sec_type == XNIFF_V2_SEC_MACH_HEADER_OPTIONS and len(payload) >= mach_pl_sz:
                    mach_pl = struct.unpack_from(MACH_PL_FMT, payload, 0)
                elif sec_type == XNIFF_V2_SEC_MACH_INLINE_BYTES:
                    inline_msg = payload
                elif sec_type == XNIFF_V2_SEC_MACH_TRAILER_BYTES:
                    trailer_bytes = payload
                elif sec_type == XNIFF_V2_SEC_MACH_DESC_META and len(payload) >= struct.calcsize(DESC_META_FMT):
                    idx, desc_type, desc_flags, address, size_bytes, count, elem_size, port_name, port_disposition, _ = (
                        struct.unpack_from(DESC_META_FMT, payload, 0)
                    )
                    d = {
                        "index": int(idx),
                        "desc_type": int(desc_type),
                        "desc_flags": int(desc_flags),
                        "address": int(address),
                        "size_bytes": int(size_bytes),
                        "count": int(count),
                        "elem_size": int(elem_size),
                        "port_name": int(port_name),
                        "port_disposition": int(port_disposition),
                    }
                    descriptors.append(d)
                    pending_desc = d
                elif sec_type in (XNIFF_V2_SEC_MACH_DESC_OOL_BYTES, XNIFF_V2_SEC_MACH_DESC_PORT_ARRAY):
                    if pending_desc is not None:
                        pending_desc["bytes"] = payload
                elif sec_type == XNIFF_V2_SEC_XPC_CALL_META and len(payload) >= xpc_pl_sz:
                    xpc_pl = struct.unpack_from(XPC_PL_FMT, payload, 0)
                    str_lens = [int(xpc_pl[13]), int(xpc_pl[14]), int(xpc_pl[15]), int(xpc_pl[16])]
                    so = xpc_pl_sz
                    for i, sl in enumerate(str_lens):
                        if sl <= 0:
                            continue
                        if so + sl > len(payload):
                            break
                        xpc_strs[i] = _decode_text(payload[so:so + sl])
                        so += sl
                elif sec_type == XNIFF_V2_SEC_XPC_SERIALIZED and len(payload) >= serial_sz:
                    slot, fmt, flags, original_len, stored_len = struct.unpack_from(XPC_SERIAL_FMT, payload, 0)
                    slot_name = _xpc_slot_name(slot)
                    avail = max(0, len(payload) - serial_sz)
                    keep = min(int(stored_len), avail)
                    raw_serialized = payload[serial_sz:serial_sz + keep]
                    serial_entry: Dict[str, Any] = {
                        "format": _xpc_format_name(fmt),
                        "stored_len": keep,
                        "original_len": int(original_len),
                        "truncated": bool(flags & 1),
                    }
                    if fmt == 1 and not (flags & 1):
                        try:
                            serial_entry["pretty"] = format_xpc_serialization(raw_serialized)
                        except XPCDecodeError as exc:
                            serial_entry["decode_error"] = str(exc)
                    serialized[slot_name] = serial_entry
                elif sec_type == XNIFF_V2_SEC_XPC_CONN_META and len(payload) >= conn_meta_sz:
                    md = struct.unpack_from(XPC_CONN_META_FMT, payload, 0)
                    flags = int(md[1])
                    pid_public = int(md[2])
                    name_public_len = int(md[-2])
                    if flags & XNIFF_XPC_CONN_META_HAS_PID_PUBLIC:
                        conn_pid_public = pid_public
                    if (flags & XNIFF_XPC_CONN_META_HAS_NAME_PUBLIC) and name_public_len > 0:
                        name_off = conn_meta_sz
                        if name_off + name_public_len <= len(payload):
                            conn_name_public = _decode_text(payload[name_off:name_off + name_public_len])
                elif sec_type == XNIFF_V2_SEC_HOOK_DIAG and len(payload) >= diag_sz:
                    msg_len, _level = struct.unpack_from(DIAG_FMT, payload, 0)
                    msg_len = min(int(msg_len), max(0, len(payload) - diag_sz))
                    ev["msg"] = _decode_text(payload[diag_sz:diag_sz + msg_len])
                elif sec_type == XNIFF_V2_SEC_BACKTRACE and len(payload) >= backtrace_hdr_sz:
                    count, _reserved = struct.unpack_from(BACKTRACE_HDR_FMT, payload, 0)
                    avail = max(0, len(payload) - backtrace_hdr_sz)
                    max_in_payload = avail // u64_sz
                    bt_count = max(0, min(int(count), BACKTRACE_MAX_FRAMES, max_in_payload))
                    pcs: List[int] = []
                    for i in range(bt_count):
                        pc = struct.unpack_from("<Q", payload, backtrace_hdr_sz + (i * u64_sz))[0]
                        if int(pc) != 0:
                            pcs.append(int(pc))
                    backtrace_frames = pcs
                elif sec_type == XNIFF_V2_SEC_BACKTRACE_SYMBOLS and len(payload) >= backtrace_syms_hdr_sz:
                    count, strings_len = struct.unpack_from(BACKTRACE_SYMS_HDR_FMT, payload, 0)
                    bt_count = max(0, min(int(count), BACKTRACE_MAX_FRAMES))
                    rec_bytes = bt_count * backtrace_sym_sz
                    rec_off = backtrace_syms_hdr_sz
                    str_off = rec_off + rec_bytes
                    str_end = min(len(payload), str_off + max(0, int(strings_len)))
                    if str_off <= len(payload) and str_off <= str_end and (rec_off + rec_bytes) <= len(payload):
                        so = str_off
                        syms: List[Dict[str, Any]] = []
                        for i in range(bt_count):
                            ro = rec_off + (i * backtrace_sym_sz)
                            pc, sym_addr, name_len, image_len = struct.unpack_from(BACKTRACE_SYM_FMT, payload, ro)
                            need = int(name_len) + int(image_len)
                            if so + need > str_end:
                                break
                            name = _decode_text(payload[so:so + int(name_len)]) if int(name_len) > 0 else ""
                            so += int(name_len)
                            image = _decode_text(payload[so:so + int(image_len)]) if int(image_len) > 0 else ""
                            so += int(image_len)
                            syms.append(
                                {
                                    "pc": int(pc),
                                    "sym_addr": int(sym_addr),
                                    "name": name,
                                    "image": image,
                                }
                            )
                        if syms:
                            backtrace_symbols = syms
                elif sec_type == XNIFF_V2_SEC_CALL_ID and len(payload) >= 8:
                    wire_call_id = int(struct.unpack_from("<Q", payload, 0)[0])

            if wire_call_id:
                wire_key = (pid, wire_call_id)
                existing_call_id = wire_call_ids.get(wire_key)
                if existing_call_id is None:
                    wire_call_ids[wire_key] = call_id
                else:
                    call_id = existing_call_id
                ev["call_id"] = call_id
                ev["wire_call_id"] = wire_call_id

            if mach_pl is not None:
                option_lo = int(mach_pl[2])
                option_hi = int(mach_pl[3])
                ret_value = int(mach_pl[8])
                msgh_size_pl = int(mach_pl[4])
                copy_len_pl = int(mach_pl[5])
                mach: Dict[str, Any] = {
                    "api": int(mach_pl[0]),
                    "direction": int(mach_pl[1]),
                    "option_lo": option_lo,
                    "option_hi": option_hi,
                    "option64": ((option_hi & 0xFFFFFFFF) << 32) | (option_lo & 0xFFFFFFFF),
                    "msgh_size": msgh_size_pl,
                    "copy_len": copy_len_pl,
                    "msg_addr": int(mach_pl[6]),
                    "aux_addr": int(mach_pl[7]),
                    "ret": ret_value,
                    "desc_count": int(mach_pl[9]),
                    "priority": int(mach_pl[10]),
                    "timeout": int(mach_pl[11]),
                    "args": [int(v) for v in mach_pl[12:20]],
                    "is_send": bool(option_lo & MACH_SEND_MSG),
                    "is_recv": bool(option_lo & MACH_RCV_MSG),
                }
                if inline_msg is not None and len(inline_msg) >= mach_msg_hdr_sz:
                    msgh_bits, msgh_size_hdr, remote, local, voucher, msgh_id = struct.unpack_from(
                        MACH_MSG_HDR_FMT, inline_msg, 0
                    )
                    mach["msgh_bits"] = int(msgh_bits)
                    mach["msgh_size"] = int(msgh_size_hdr)
                    mach["msgh_id"] = int(msgh_id)
                    mach["remote"] = int(remote)
                    mach["local"] = int(local)
                    mach["voucher"] = int(voucher)
                    msz = min(int(msgh_size_hdr), len(inline_msg))
                    if msz <= mach_msg_hdr_sz:
                        mach["body_bytes"] = b""
                    else:
                        mach["body_bytes"] = inline_msg[mach_msg_hdr_sz:msz]
                elif inline_msg is not None:
                    mach["body_bytes"] = inline_msg
                if trailer_bytes is not None:
                    mach["trailer_bytes"] = trailer_bytes
                if descriptors:
                    mach["descriptors"] = descriptors
                ev["mach"] = mach

            if backtrace_frames:
                ev["backtrace"] = backtrace_frames
            elif backtrace_symbols:
                ev["backtrace"] = [_as_int(sym.get("pc"), 0) for sym in backtrace_symbols if isinstance(sym, dict)]
            if backtrace_symbols:
                ev["backtrace_symbols"] = backtrace_symbols

            if xpc_pl is not None:
                func = int(xpc_pl[2])
                conn_pid = int(xpc_pl[3]) or conn_pid_public
                ret_value = int(xpc_pl[4])
                args = [int(v) for v in xpc_pl[5:13]]
                kind_name = _entry_kind(XNIFF_API_XPC_HL, int(xpc_pl[1]))
                flow = _xpc_flow(func)
                conn_ptr = 0
                if func == XNIFF_XPC_FUNC_CONNECTION_CREATE:
                    if kind_name == "xpc_exit" and ret_value != 0:
                        conn_ptr = ret_value
                else:
                    conn_ptr = args[0]
                msg_ptr = 0
                if func in (
                    XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE,
                    XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY,
                    XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC,
                    XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER,
                    XNIFF_XPC_FUNC_PIPE_ROUTINE,
                    XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE,
                    XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC,
                    XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC,
                ):
                    msg_ptr = args[1]

                string_fields: Dict[str, str] = {}
                names = _xpc_string_field_names(kind_name, func)
                for i, s in enumerate(xpc_strs):
                    if not s:
                        continue
                    nm = names[i] if i < len(names) else None
                    string_fields[nm if nm else f"slot_{i}"] = s

                args_named: Dict[str, str] = {}
                for i, av in enumerate(args):
                    nm = _xpc_arg_name(func, i)
                    if nm:
                        args_named[nm] = f"0x{av:x}"

                xpc: Dict[str, Any] = {
                    "func": func,
                    "func_name": _xpc_func_name(func),
                    "ret": ret_value,
                    "conn_pid": conn_pid,
                    "flow": flow,
                    "role": _xpc_role(func, int(xpc_pl[1])),
                    "peer_role": _xpc_peer_role(flow),
                    "conn_ptr": f"0x{conn_ptr:x}",
                    "msg_ptr": f"0x{msg_ptr:x}",
                    "args_named": args_named,
                }
                if string_fields:
                    xpc["string_fields"] = string_fields
                if serialized:
                    xpc["serialized"] = serialized
                if conn_name_public:
                    xpc["conn_name"] = conn_name_public
                service_name = string_fields.get("target_service_name") or string_fields.get("connection_name")
                if service_name:
                    xpc["service_name"] = service_name
                ev["xpc"] = xpc

            yield ev


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
    bmode = _looks_like_binary(path)
    if bmode:
        yield from _iter_binary_events(path, bmode)
        return

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


def _parse_predicate(expr: str) -> Tuple[str, str, str]:
    m = re.match(r"^\s*([A-Za-z0-9_.-]+)\s*(==|!=|>=|<=|>|<|=)\s*(.+?)\s*$", expr)
    if not m:
        raise ValueError(f"invalid predicate: {expr!r}")
    field, op, raw = m.group(1), m.group(2), m.group(3)
    if op == "=":
        op = "=="
    return field, op, raw


def _parse_value(raw: str) -> Any:
    s = raw.strip()
    if len(s) >= 2 and ((s[0] == s[-1] == '"') or (s[0] == s[-1] == "'")):
        return s[1:-1]
    lo = s.lower()
    if lo == "true":
        return True
    if lo == "false":
        return False
    try:
        if s.startswith(("0x", "0X")):
            return int(s, 16)
        return int(s, 10)
    except ValueError:
        pass
    try:
        return float(s)
    except ValueError:
        return s


def _to_num(v: Any) -> Optional[float]:
    if isinstance(v, bool):
        return float(int(v))
    if isinstance(v, (int, float)):
        return float(v)
    if isinstance(v, str):
        t = v.strip()
        try:
            if t.startswith(("0x", "0X")):
                return float(int(t, 16))
            return float(t)
        except ValueError:
            return None
    return None


def _field_aliases() -> Dict[str, str]:
    return {
        "descriptor_count": "mach.desc_count",
        "desc_count": "mach.desc_count",
        "remote": "mach.remote",
        "local": "mach.local",
        "msgh_id": "mach.msgh_id",
        "api": "mach.api",
        "func": "xpc.func",
        "conn_pid": "xpc.conn_pid",
    }


def _event_field_value(ev: Dict[str, Any], field: str) -> Any:
    if field in ("descriptor_count", "desc_count"):
        mach = ev.get("mach")
        if isinstance(mach, dict):
            descs = mach.get("descriptors")
            if isinstance(descs, list):
                return len(descs)
            return mach.get("desc_count")
        return None
    path = _field_aliases().get(field, field)
    cur: Any = ev
    for part in path.split("."):
        if not isinstance(cur, dict):
            return None
        cur = cur.get(part)
    return cur


def _event_matches_predicate(ev: Dict[str, Any], pred: Tuple[str, str, Any]) -> bool:
    field, op, rhs = pred
    lhs = _event_field_value(ev, field)
    if lhs is None:
        return False

    ln = _to_num(lhs)
    rn = _to_num(rhs)
    if ln is not None and rn is not None:
        if op == "==":
            return ln == rn
        if op == "!=":
            return ln != rn
        if op == ">":
            return ln > rn
        if op == ">=":
            return ln >= rn
        if op == "<":
            return ln < rn
        if op == "<=":
            return ln <= rn
        return False

    ls = str(lhs)
    rs = str(rhs)
    if op == "==":
        return ls == rs
    if op == "!=":
        return ls != rs
    if op == ">":
        return ls > rs
    if op == ">=":
        return ls >= rs
    if op == "<":
        return ls < rs
    if op == "<=":
        return ls <= rs
    return False


def _event_matches_predicates(ev: Dict[str, Any], preds: List[Tuple[str, str, Any]]) -> bool:
    for p in preds:
        if not _event_matches_predicate(ev, p):
            return False
    return True


def _hexdump(data: bytes, max_bytes: int = 256) -> str:
    if not data:
        return ""
    n = min(len(data), max_bytes)
    lines: List[str] = []
    for off in range(0, n, 16):
        chunk = data[off:off + 16]
        hex_part = " ".join(f"{b:02x}" for b in chunk)
        hex_part = f"{hex_part:<47}"
        asc = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        lines.append(f"    {off:04x} : {hex_part}  |{asc}|")
    if len(data) > max_bytes:
        lines.append(f"    ... truncated ({len(data) - max_bytes} bytes omitted)")
    return "\n".join(lines)


def _backtrace_lines(ev: Dict[str, Any]) -> List[str]:
    bt = ev.get("backtrace")
    if not isinstance(bt, list) or not bt:
        return []

    sym_list = ev.get("backtrace_symbols")
    out: List[str] = []
    for i, pc in enumerate(bt[:BACKTRACE_MAX_FRAMES]):
        pcv = _as_int(pc, 0)
        line = f"  #{i}: 0x{pcv:x}"
        sym: Optional[Dict[str, Any]] = None
        if isinstance(sym_list, list) and i < len(sym_list) and isinstance(sym_list[i], dict):
            sym = sym_list[i]
        if sym:
            name = sym.get("name")
            image = sym.get("image")
            sym_addr = _as_int(sym.get("sym_addr"), 0)
            if isinstance(name, str) and name:
                line += f" {name}"
                if sym_addr != 0 and pcv >= sym_addr:
                    line += f"+0x{(pcv - sym_addr):x}"
            elif sym_addr != 0 and pcv >= sym_addr:
                line += f" +0x{(pcv - sym_addr):x}"
            if isinstance(image, str) and image:
                line += f" ({image})"
        out.append(line)
    return out


def _disp_name(v: int) -> str:
    table = {
        16: "MOVE_RECEIVE",
        17: "MOVE_SEND",
        18: "MOVE_SEND_ONCE",
        19: "COPY_SEND",
        20: "MAKE_SEND",
        21: "MAKE_SEND_ONCE",
        22: "COPY_RECEIVE",
        24: "DISPOSE_RECEIVE",
        25: "DISPOSE_SEND",
        26: "DISPOSE_SEND_ONCE",
    }
    return table.get(v, "UNKNOWN")


def _mach_desc_type_name(v: int) -> str:
    return {
        0: "PORT",
        1: "OOL",
        2: "OOL_PORTS",
        3: "OOL_VOLATILE",
    }.get(v, f"TYPE_{v}")


def _mach_option_flags(opt: int) -> List[str]:
    out: List[str] = []
    if opt & 0x00000001:
        out.append("SEND_MSG")
    if opt & 0x00000002:
        out.append("RCV_MSG")
    if opt & 0x00000004:
        out.append("RCV_LARGE")
    if opt & 0x00000008:
        out.append("RCV_LARGE_IDENTITY")
    if opt & 0x00000010:
        out.append("SEND_TIMEOUT")
    if opt & 0x00000100:
        out.append("SEND_INTERRUPT")
    if opt & 0x00000400:
        out.append("SEND_ALWAYS")
    if opt & 0x00001000:
        out.append("RCV_TIMEOUT")
    if opt & 0x00004000:
        out.append("RCV_INTERRUPT")
    return out


def _mach_bits_flags(bits: int) -> List[str]:
    out: List[str] = []
    if bits & 0x80000000:
        out.append("COMPLEX")
    return out


def _mach_text(ev: Dict[str, Any]) -> Optional[str]:
    mach = ev.get("mach")
    if not isinstance(mach, dict):
        return None
    if not any(
        k in mach
        for k in (
            "option64",
            "msgh_bits",
            "msgh_size",
            "msg_addr",
            "body_bytes",
            "descriptors",
            "trailer_bytes",
        )
    ):
        return None

    opt64 = _as_int(mach.get("option64"), 0)
    bits = _as_int(mach.get("msgh_bits"), 0)
    msgh_size = _as_int(mach.get("msgh_size"), 0)
    remote = _as_int(mach.get("remote"), 0)
    local = _as_int(mach.get("local"), 0)
    voucher = _as_int(mach.get("voucher"), 0)
    msgh_id = _as_int(mach.get("msgh_id"), 0)
    msg_addr = _as_int(mach.get("msg_addr"), 0)
    ret = _as_int(mach.get("ret"), 0)

    remote_disp = bits & 0xFF
    local_disp = (bits >> 8) & 0xFF
    voucher_disp = (bits >> 16) & 0xFF

    out: List[str] = []
    out.append(f"address: 0x{msg_addr:x}")
    out.append(f"options : 0x{opt64:08x}")
    flags = _mach_option_flags(opt64)
    out.append(f"  flags : {' '.join(flags) if flags else '(none)'}")
    out.append(f"msgh_bits: 0x{bits:08x}")
    out.append(f"  remote disp : 0x{remote_disp:02x} ({_disp_name(remote_disp)})")
    out.append(f"  local  disp : 0x{local_disp:02x} ({_disp_name(local_disp)})")
    out.append(f"  voucher disp: 0x{voucher_disp:02x} ({_disp_name(voucher_disp)})")
    bflags = _mach_bits_flags(bits)
    out.append(f"  flags       : {' '.join(bflags) if bflags else '(none)'}")
    out.append(f"size   : {msgh_size} bytes")
    out.append(f"remote : 0x{remote:08x}")
    out.append(f"local  : 0x{local:08x}")
    out.append(f"voucher: 0x{voucher:08x}")
    out.append(f"msgh_id: {msgh_id} (0x{msgh_id:08x})")
    out.append(f"return value: 0x{ret:x}")

    body_bytes = mach.get("body_bytes")
    if isinstance(body_bytes, (bytes, bytearray)):
        if len(body_bytes) == 0:
            out.append("body   : <no body> (msgh_size <= sizeof(header))")
        else:
            out.append(f"body   : {len(body_bytes)} bytes")
            hd = _hexdump(bytes(body_bytes), 512)
            if hd:
                out.append(hd)
    elif msgh_size <= struct.calcsize(MACH_MSG_HDR_FMT):
        out.append("body   : <no body> (msgh_size <= sizeof(header))")

    trailer = mach.get("trailer_bytes")
    if isinstance(trailer, (bytes, bytearray)) and len(trailer) > 0:
        out.append(f"trailer: {len(trailer)} bytes")
        hd = _hexdump(bytes(trailer), 256)
        if hd:
            out.append(hd)

    descs = mach.get("descriptors")
    header_desc_count: Optional[int] = None
    if "desc_count" in mach:
        header_desc_count = _as_int(mach.get("desc_count"), 0)
    if isinstance(descs, list):
        captured_desc_count = len(descs)
        if header_desc_count is None:
            out.append(f"descriptor_count: {captured_desc_count}")
        elif header_desc_count == captured_desc_count:
            out.append(f"descriptor_count: {captured_desc_count}")
        else:
            out.append(f"descriptor_count: {captured_desc_count} (header={header_desc_count})")
        for i, d in enumerate(descs):
            if not isinstance(d, dict):
                continue
            dtyp = _as_int(d.get("desc_type"), 0)
            dname = _mach_desc_type_name(dtyp)
            daddr = _as_int(d.get("address"), 0)
            dsz = _as_int(d.get("size_bytes"), 0)
            dflags = _as_int(d.get("desc_flags"), 0)
            line = f"descriptor[{i}]: {dname}"
            if dname in ("OOL", "OOL_VOLATILE"):
                line += f" addr=0x{daddr:x} size={dsz} deallocate={1 if (dflags & 1) else 0} copy={1 if (dflags & 2) else 0}"
            elif dname == "OOL_PORTS":
                line += f" addr=0x{daddr:x} bytes={dsz} count={_as_int(d.get('count'), 0)} elem_size={_as_int(d.get('elem_size'), 0)} disp={dflags}"
            elif dname == "PORT":
                line += f" name=0x{_as_int(d.get('port_name'), 0):08x} disp={_as_int(d.get('port_disposition'), 0)}"
            out.append(line)
            dbytes = d.get("bytes")
            if isinstance(dbytes, (bytes, bytearray)) and len(dbytes) > 0:
                out.append(f"  data: {len(dbytes)} bytes")
                hd = _hexdump(bytes(dbytes), 512)
                if hd:
                    out.append(hd)
    elif header_desc_count is not None:
        out.append(f"descriptor_count: {header_desc_count}")

    bt_lines = _backtrace_lines(ev)
    if bt_lines:
        out.append("backtrace:")
        out.extend(bt_lines)

    return "\n".join(out) if out else None


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


def _has_mach_detail(ev: Dict[str, Any]) -> bool:
    mach = ev.get("mach")
    if not isinstance(mach, dict):
        return False
    return any(
        k in mach
        for k in (
            "msgh_bits",
            "msgh_size",
            "option64",
            "body_bytes",
            "descriptors",
            "trailer_bytes",
        )
    )


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
    if use_mach_pretty and (_has_xpc_pretty(ev) or _has_mach_detail(ev)):
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
            decode_error = ent.get("decode_error")
            if isinstance(decode_error, str) and decode_error:
                parts.append(f"serialized.{slot}.decode_error: {decode_error}")

    bt_lines = _backtrace_lines(ev)
    if bt_lines:
        parts.append("backtrace:")
        parts.extend(bt_lines)

    return parts


def _xpc_text(ev: Dict[str, Any], *, use_mach_pretty: bool, use_hl_strings: bool) -> Optional[str]:
    blocks: List[str] = []

    if use_mach_pretty:
        p = _get(ev, "xpc", "pretty", default=None)
        if isinstance(p, str) and p:
            blocks.append(p)
        m = _mach_text(ev)
        if isinstance(m, str) and m:
            blocks.append(m)

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
    if not ts:
        mono = _as_float(ev.get("ts_mono_s"), 0.0)
        if mono:
            ts = f"mono:{mono:.6f}s"
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
        role = _get(ev, "xpc", "role", default=None)
        xpc_peer_role = _get(ev, "xpc", "peer_role", default=None)
        service_name = _get(ev, "xpc", "service_name", default=None)
        conn_ptr = _get(ev, "xpc", "conn_ptr", default=None)
        msg_ptr = _get(ev, "xpc", "msg_ptr", default=None)
        conn_seq = _as_int(_get(ev, "xpc", "conn_seq", default=0), 0)
        response_to_event_id = _as_int(_get(ev, "xpc", "response_to_event_id", default=0), 0)
        extra += f" func={xpc_func}"
        if isinstance(flow, str) and flow:
            extra += f" flow={flow}"
        if isinstance(role, str) and role:
            extra += f" role={role}"
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
            "Input may be an xniff dump (--out), JSON lines, or a JSON array."
        )
    )
    ap.add_argument("events_path", help="Path to .xniffbin, JSONL, or JSON array capture")
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
    ap.add_argument(
        "--filter",
        action="append",
        default=[],
        help="Event predicate, e.g. --filter 'descriptor_count >= 1' (can repeat; ANDed)",
    )
    ap.add_argument("--min-call-id", type=int, default=None, help="Only include call_id >= N")
    ap.add_argument("--max-call-id", type=int, default=None, help="Only include call_id <= N")
    args = ap.parse_args(argv)

    if args.mach_only and args.hl_only:
        print("error: --mach-only and --hl-only are mutually exclusive", file=sys.stderr)
        return 2
    use_mach_pretty = not args.hl_only
    use_hl_strings = not args.mach_only
    predicates: List[Tuple[str, str, Any]] = []
    try:
        for expr in args.filter:
            field, op, raw = _parse_predicate(expr)
            predicates.append((field, op, _parse_value(raw)))
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2

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
        if predicates and not _event_matches_predicates(ev, predicates):
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
        print("Tip: capture with: xniff-cli attach <pid> --xpc --out capture.xniffbin", file=sys.stderr)
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
        entry_role = _get(entry or {}, "xpc", "role", default=None)
        exit_role = _get(exit_ev or {}, "xpc", "role", default=None)

        paired_from = ""
        if exit_ev is not None and isinstance(exit_ev.get("call_id"), int) and exit_ev.get("call_id") != b.call_id:
            paired_from = f" paired_call_id={exit_ev.get('call_id')}"

        # Only call it a RESPONSE when a receive actually happens (possibly paired from a later call_id).
        if entry_role == "request" and exit_role == "response":
            if args.only_pairs and (entry is None or exit_ev is None):
                continue
            sys.stdout.write(
                _render_event(entry, "REQUEST", use_mach_pretty=use_mach_pretty, use_hl_strings=use_hl_strings)
            )
            sys.stdout.write(
                _render_event(exit_ev, "RESPONSE", use_mach_pretty=use_mach_pretty,
                              use_hl_strings=use_hl_strings, extra=paired_from)
            )
        elif entry_role == "response":
            if args.only_pairs:
                continue
            sys.stdout.write(
                _render_event(entry, "RESPONSE", use_mach_pretty=use_mach_pretty, use_hl_strings=use_hl_strings)
            )
        elif entry_role == "incoming":
            if args.only_pairs:
                continue
            sys.stdout.write(
                _render_event(entry, "INCOMING", use_mach_pretty=use_mach_pretty, use_hl_strings=use_hl_strings)
            )
        elif entry_send and (entry_recv or exit_recv):
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
