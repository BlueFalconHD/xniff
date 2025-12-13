#!/usr/bin/env python3
import argparse
import shlex
import lldb


def _parse_int(s: str) -> int:
    s = s.strip()
    return int(s, 0)


def _get_general_registers(frame: lldb.SBFrame):
    regs = frame.GetRegisters()
    for regset in regs:
        name = (regset.GetName() or "").lower()
        if "general" in name or "gpr" in name:
            return regset
    return None


def _snapshot_state(frame: lldb.SBFrame):
    regset = _get_general_registers(frame)
    out = {}
    if not regset:
        return out
    for reg in regset:
        rname = reg.GetName()
        if not rname:
            continue
        out[rname.lower()] = reg.GetValueAsUnsigned()
    return out


def _nzcv_from_state(state: dict):
    if "nzcv" in state:
        return state["nzcv"] & 0xF
    if "cpsr" in state:
        # NZCV are the top 4 bits of PSTATE/CPSR on AArch64.
        return (state["cpsr"] >> 28) & 0xF
    return None


class _Session:
    def __init__(self, target: lldb.SBTarget, entry_bp_id: int, exit_bp_id: int, ignore, once: bool, stop_on_mismatch: bool):
        self.target = target
        self.entry_bp_id = entry_bp_id
        self.exit_bp_id = exit_bp_id
        self.ignore = set(x.lower() for x in ignore)
        self.once = once
        self.stop_on_mismatch = stop_on_mismatch
        # thread-id -> list[dict]
        self.stack_by_thread = {}

    def push(self, thread_id: int, state: dict):
        self.stack_by_thread.setdefault(thread_id, []).append(state)

    def pop(self, thread_id: int):
        st = self.stack_by_thread.get(thread_id)
        if not st:
            return None
        val = st.pop()
        if not st:
            self.stack_by_thread.pop(thread_id, None)
        return val


_sessions_by_bp_id = {}


def _delete_breakpoints(session: _Session):
    try:
        session.target.BreakpointDelete(session.entry_bp_id)
    except Exception:
        pass
    try:
        session.target.BreakpointDelete(session.exit_bp_id)
    except Exception:
        pass


def xniff_regcheck_entry(frame: lldb.SBFrame, bp_loc, _dict):
    bp = bp_loc.GetBreakpoint()
    session = _sessions_by_bp_id.get(bp.GetID())
    if not session:
        return False  # auto-continue

    thread = frame.GetThread()
    tid = thread.GetThreadID()
    session.push(tid, _snapshot_state(frame))
    return False  # auto-continue


def xniff_regcheck_exit(frame: lldb.SBFrame, bp_loc, _dict):
    bp = bp_loc.GetBreakpoint()
    session = _sessions_by_bp_id.get(bp.GetID())
    if not session:
        return False  # auto-continue

    thread = frame.GetThread()
    tid = thread.GetThreadID()
    before = session.pop(tid)
    after = _snapshot_state(frame)

    if not before:
        # No matching entry captured; keep running.
        return False

    mismatches = []
    for k, v in before.items():
        if k in session.ignore:
            continue
        if k == "pc":
            continue
        if k not in after:
            mismatches.append((k, v, None))
            continue
        if after[k] != v:
            mismatches.append((k, v, after[k]))

    # NZCV handling (if available)
    nz0 = _nzcv_from_state(before)
    nz1 = _nzcv_from_state(after)
    if nz0 is not None and nz1 is not None and nz0 != nz1:
        mismatches.append(("nzcv", nz0, nz1))

    if mismatches:
        msg = ["[xniff] register mismatch in trampoline stub:"]
        for (name, a, b) in mismatches:
            if b is None:
                msg.append(f"  {name}: entry=0x{a:x} exit=<missing>")
            else:
                msg.append(f"  {name}: entry=0x{a:x} exit=0x{b:x}")
        for line in msg:
            print(line)
        if session.once:
            _delete_breakpoints(session)
        return True if session.stop_on_mismatch else False

    if session.once:
        _delete_breakpoints(session)
    return False


def xniff_regcheck_command(debugger, command, result, _dict):
    """
    Usage:
      xniff-regcheck --entry 0xADDR --exit 0xADDR [--ignore x16,x17] [--once] [--stop-on-mismatch]

    Notes:
    - Provide `--entry` at the trampoline stub entry *after stolen instructions*.
    - Provide `--exit` at a point where the stub has restored state (e.g. the printed `after_restore` address).
    """
    try:
        argv = shlex.split(command)
        ap = argparse.ArgumentParser(prog="xniff-regcheck", add_help=False)
        ap.add_argument("--entry", required=True)
        ap.add_argument("--exit", dest="exit_", required=True)
        ap.add_argument("--ignore", default="")
        ap.add_argument("--once", action="store_true")
        ap.add_argument("--stop-on-mismatch", action="store_true")
        ap.add_argument("-h", "--help", action="store_true")
        ns = ap.parse_args(argv)
        if ns.help:
            result.PutCString(xniff_regcheck_command.__doc__)
            return
    except SystemExit:
        result.PutCString(xniff_regcheck_command.__doc__)
        return
    except Exception as e:
        result.PutCString(f"[xniff] arg parse failed: {e}")
        result.PutCString(xniff_regcheck_command.__doc__)
        return

    target = debugger.GetSelectedTarget()
    if not target or not target.IsValid():
        result.PutCString("[xniff] no selected target")
        return

    entry_addr = _parse_int(ns.entry)
    exit_addr = _parse_int(ns.exit_)
    ignore = [x.strip() for x in ns.ignore.split(",") if x.strip()]

    bp_entry = target.BreakpointCreateByAddress(entry_addr)
    bp_exit = target.BreakpointCreateByAddress(exit_addr)
    if not bp_entry.IsValid() or not bp_exit.IsValid():
        result.PutCString("[xniff] failed to create breakpoints")
        return

    # Register callbacks
    bp_entry.SetScriptCallbackFunction(__name__ + ".xniff_regcheck_entry")
    bp_exit.SetScriptCallbackFunction(__name__ + ".xniff_regcheck_exit")

    session = _Session(target, bp_entry.GetID(), bp_exit.GetID(), ignore, ns.once, ns.stop_on_mismatch)
    _sessions_by_bp_id[bp_entry.GetID()] = session
    _sessions_by_bp_id[bp_exit.GetID()] = session

    result.PutCString(
        "[xniff] regcheck armed: "
        f"entry=0x{entry_addr:x} exit=0x{exit_addr:x} "
        f"(entry_bp={bp_entry.GetID()} exit_bp={bp_exit.GetID()})"
    )


def __lldb_init_module(debugger, _dict):
    debugger.HandleCommand(f"command script add -f {__name__}.xniff_regcheck_command xniff-regcheck")
    print("[xniff] loaded xniff-regcheck (use: xniff-regcheck --help)")
