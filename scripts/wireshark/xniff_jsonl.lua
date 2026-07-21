-- XNIFF Wireshark plugin:
-- 1) custom FileHandler for JSONL captures
-- 2) custom FileHandler for binary .xniffbin captures
-- 3) protocol split in packet list (XPC/MACH) for binary captures

local XNIFF_JSON_ENCAP = (wtap and wtap.USER12) or (wtap and wtap.USER0)
local XNIFF_DIAG_ENCAP = (wtap and wtap.USER13) or (wtap and wtap.USER0)
local XNIFF_MACH_ENCAP = (wtap and wtap.USER14) or (wtap and wtap.USER0)
local XNIFF_XPC_ENCAP = (wtap and wtap.USER15) or (wtap and wtap.USER0)
local XNIFF_ENCAP = XNIFF_JSON_ENCAP
if not XNIFF_JSON_ENCAP or not XNIFF_MACH_ENCAP or not XNIFF_XPC_ENCAP then
    return
end

local json_dissector = Dissector.get("json")

local xniff = Proto("xniff", "XNIFF JSONL")

local function safe_field(make, ...)
    local ok, v = pcall(make, ...)
    if ok then return v end
    return nil
end

local f_schema = safe_field(ProtoField.string, "xniff.schema", "Schema")
local f_event_id = safe_field(ProtoField.uint32, "xniff.event_id", "Event ID", base.DEC)
local f_call_id = safe_field(ProtoField.uint32, "xniff.call_id", "Call ID", base.DEC)
local f_entry_event_id = safe_field(ProtoField.uint32, "xniff.entry_event_id", "Entry Event ID", base.DEC)
local f_kind = safe_field(ProtoField.string, "xniff.kind", "Kind")
local f_pid = safe_field(ProtoField.uint32, "xniff.pid", "PID", base.DEC)
local f_tid_low = safe_field(ProtoField.uint32, "xniff.tid_low", "Thread Low", base.HEX)
local f_proc_name = safe_field(ProtoField.string, "xniff.proc_name", "Process Name")
local f_flow = safe_field(ProtoField.string, "xniff.flow", "XPC Flow")
local f_role = safe_field(ProtoField.string, "xniff.role", "XPC Role")
local f_func_name = safe_field(ProtoField.string, "xniff.func_name", "Function")
local f_api = safe_field(ProtoField.uint32, "xniff.api", "API", base.DEC)
local f_direction = safe_field(ProtoField.uint32, "xniff.direction", "Direction", base.DEC)
local f_seq = safe_field(ProtoField.string, "xniff.seq", "Sequence")
local f_function = safe_field(ProtoField.uint32, "xniff.function", "Function Code", base.DEC)
local f_payload_view = safe_field(ProtoField.string, "xniff.payload_view", "Payload View")
local f_conn_seq = safe_field(ProtoField.uint32, "xniff.conn_seq", "Connection Sequence", base.DEC)
local f_response_to_event_id = safe_field(ProtoField.uint32, "xniff.response_to_event_id", "Response To Event ID", base.DEC)
local f_conn_pid = safe_field(ProtoField.uint32, "xniff.conn_pid", "Connection PID", base.DEC)
local f_conn_name = safe_field(ProtoField.string, "xniff.conn_name", "Connection Name")
local f_service_name = safe_field(ProtoField.string, "xniff.service_name", "Service Name")
local f_conn_ptr = safe_field(ProtoField.string, "xniff.conn_ptr", "Connection Ptr")
local f_msg_ptr = safe_field(ProtoField.string, "xniff.msg_ptr", "Message Ptr")
local f_has_serialized_message = safe_field(ProtoField.bool, "xniff.has_serialized_message", "Has Serialized Message")
local f_has_serialized_reply = safe_field(ProtoField.bool, "xniff.has_serialized_reply", "Has Serialized Reply")
local f_has_serialized_event = safe_field(ProtoField.bool, "xniff.has_serialized_event", "Has Serialized Event")
local f_serialized_message_len = safe_field(ProtoField.uint32, "xniff.serialized_message_len", "Serialized Message Length", base.DEC)
local f_serialized_reply_len = safe_field(ProtoField.uint32, "xniff.serialized_reply_len", "Serialized Reply Length", base.DEC)
local f_serialized_event_len = safe_field(ProtoField.uint32, "xniff.serialized_event_len", "Serialized Event Length", base.DEC)

xniff.fields = {
    f_schema,
    f_event_id,
    f_call_id,
    f_entry_event_id,
    f_kind,
    f_pid,
    f_tid_low,
    f_proc_name,
    f_flow,
    f_role,
    f_func_name,
    f_api,
    f_direction,
    f_seq,
    f_function,
    f_payload_view,
    f_conn_seq,
    f_response_to_event_id,
    f_conn_pid,
    f_conn_name,
    f_service_name,
    f_conn_ptr,
    f_msg_ptr,
    f_has_serialized_message,
    f_has_serialized_reply,
    f_has_serialized_event,
    f_serialized_message_len,
    f_serialized_reply_len,
    f_serialized_event_len,
}

local function trim(s)
    if not s then return "" end
    return (s:gsub("^%s+", ""):gsub("%s+$", ""))
end

local function unescape_json_string(s)
    if not s then return nil end
    local out = s
    out = out:gsub("\\\"", "\"")
    out = out:gsub("\\\\", "\\")
    out = out:gsub("\\/", "/")
    out = out:gsub("\\b", "\b")
    out = out:gsub("\\f", "\f")
    out = out:gsub("\\n", "\n")
    out = out:gsub("\\r", "\r")
    out = out:gsub("\\t", "\t")
    return out
end

local function find_json_string(line, key)
    local patt = '"' .. key .. '"%s*:%s*"'
    local _, stop = line:find(patt)
    if not stop then return nil end

    local i = stop + 1
    local start = i
    while i <= #line do
        local c = line:sub(i, i)
        if c == "\\" then
            i = i + 2
        elseif c == '"' then
            return unescape_json_string(line:sub(start, i - 1))
        else
            i = i + 1
        end
    end
    return nil
end

local function find_json_int(line, key)
    local patt = '"' .. key .. '"%s*:%s*(-?%d+)'
    local s = line:match(patt)
    if not s then return nil end
    return tonumber(s)
end

local function find_json_nullable_int(line, key)
    local patt = '"' .. key .. '"%s*:%s*([^,%}%s]+)'
    local raw = line:match(patt)
    if not raw then return nil end
    if raw == "null" then return nil end
    return tonumber(raw)
end

local function parse_ts_real(line)
    local y, mo, d, h, mi, s, frac =
        line:match('"ts_real"%s*:%s*"(%d%d%d%d)%-(%d%d)%-(%d%d) (%d%d):(%d%d):(%d%d)%.(%d+)"')
    if not y then return nil, nil end
    local sec = os.time({
        year = tonumber(y),
        month = tonumber(mo),
        day = tonumber(d),
        hour = tonumber(h),
        min = tonumber(mi),
        sec = tonumber(s),
    })
    if not sec then return nil, nil end
    local nsec = tonumber((frac .. "000000000"):sub(1, 9)) or 0
    return sec, nsec
end

local function parse_ts_mono(line)
    local s = line:match('"ts_mono_s"%s*:%s*([%-%d%.eE]+)')
    if not s then return nil end
    return tonumber(s)
end

local function nstime_new(sec, nsec)
    if not NSTime then return nil end
    if type(NSTime.new) == "function" then
        local ok, v = pcall(NSTime.new, sec, nsec)
        if ok then return v end
    end
    local ok, v = pcall(NSTime, sec, nsec)
    if ok then return v end
    return nil
end

local function update_time_from_line(line, state)
    local sec, nsec = parse_ts_real(line)
    if sec then return sec, nsec end

    local mono = parse_ts_mono(line)
    if mono then
        if not state.base_mono then
            state.base_mono = mono
            state.base_epoch = os.time()
        end
        local delta = mono - state.base_mono
        if delta < 0 then delta = 0 end
        local whole = math.floor(delta)
        local frac = delta - whole
        sec = state.base_epoch + whole
        nsec = math.floor((frac * 1000000000.0) + 0.5)
        if nsec >= 1000000000 then
            sec = sec + 1
            nsec = nsec - 1000000000
        end
        return sec, nsec
    end

    return os.time(), 0
end

local function find_slot_chunk(line, slot_name)
    local s_start, s_end = line:find('"serialized"%s*:%s*%b{}')
    if not s_start then return nil end
    local block = line:sub(s_start, s_end)
    local patt = '"' .. slot_name .. '"%s*:%s*(%b{})'
    return block:match(patt)
end

local function slot_has_data(line, slot_name)
    local chunk = find_slot_chunk(line, slot_name)
    if not chunk then return false, nil end
    local stored = tonumber(chunk:match('"stored_len"%s*:%s*(%d+)'))
    return true, stored
end

local function hex_to_bin(hex)
    if not hex then return nil, "missing hex" end
    if (#hex % 2) ~= 0 then return nil, "odd hex length" end
    local out = {}
    for i = 1, #hex, 2 do
        local b = tonumber(hex:sub(i, i + 1), 16)
        if not b then
            return nil, "invalid hex at byte " .. tostring(math.floor((i + 1) / 2))
        end
        out[#out + 1] = string.char(b)
    end
    return table.concat(out)
end

local function bytes_to_hex(bin, max_bytes)
    if not bin then return "" end
    local n = #bin
    local cut = false
    if max_bytes and n > max_bytes then
        n = max_bytes
        cut = true
    end
    local t = {}
    for i = 1, n do
        t[#t + 1] = string.format("%02x", bin:byte(i))
    end
    local s = table.concat(t)
    if cut then s = s .. "..." end
    return s
end

local function safe_ascii(s, max_len)
    if not s then return "" end
    local out = s
    local cut = false
    if max_len and #out > max_len then
        out = out:sub(1, max_len)
        cut = true
    end
    out = out:gsub("[%z\1-\31\127]", function(c)
        return string.format("\\x%02x", string.byte(c))
    end)
    if cut then out = out .. "..." end
    return out
end

local function find_slot_wire_hex(line, slot_name)
    local chunk = find_slot_chunk(line, slot_name)
    if not chunk then return nil end
    local wire_hex = chunk:match('"wire_hex"%s*:%s*"([0-9a-fA-F]*)"')
    local format_name = chunk:match('"format"%s*:%s*"([^"]+)"')
    local stored_len = tonumber(chunk:match('"stored_len"%s*:%s*(%d+)'))
    local original_len = tonumber(chunk:match('"original_len"%s*:%s*(%d+)'))
    local truncated = chunk:match('"truncated"%s*:%s*(true)') ~= nil
    return {
        present = true,
        slot = slot_name,
        chunk = chunk,
        wire_hex = wire_hex,
        format_name = format_name,
        stored_len = stored_len,
        original_len = original_len,
        truncated = truncated,
    }
end

local function stream_new(bin, start_off)
    return {
        buf = bin or "",
        len = #(bin or ""),
        ofs = start_off or 0, -- byte offset (0-based)
    }
end

local function stream_tell(st) return st.ofs end

local function stream_remaining(st)
    local rem = st.len - st.ofs
    if rem < 0 then return 0 end
    return rem
end

local function stream_seek(st, off)
    if off < 0 or off > st.len then return false end
    st.ofs = off
    return true
end

local function stream_read_bytes(st, n)
    if n < 0 then return nil end
    if st.ofs + n > st.len then return nil end
    local s = st.buf:sub(st.ofs + 1, st.ofs + n)
    st.ofs = st.ofs + n
    return s
end

local function stream_read_u8(st)
    local b = stream_read_bytes(st, 1)
    if not b then return nil end
    return b:byte(1)
end

local function stream_read_u32_le(st)
    local b = stream_read_bytes(st, 4)
    if not b then return nil end
    local b1, b2, b3, b4 = b:byte(1, 4)
    return b1 + b2 * 0x100 + b3 * 0x10000 + b4 * 0x1000000
end

local function stream_read_u64_parts(st)
    local lo = stream_read_u32_le(st)
    if not lo then return nil, nil end
    local hi = stream_read_u32_le(st)
    if not hi then return nil, nil end
    return lo, hi
end

local function stream_align4(st)
    local aligned = math.floor((st.ofs + 3) / 4) * 4
    if aligned > st.len then aligned = st.len end
    st.ofs = aligned
end

local function u64_hex(hi, lo)
    return string.format("0x%08x%08x", hi, lo)
end

local function u64_to_number_safe(hi, lo)
    if hi < 0x200000 then
        return hi * 4294967296.0 + lo
    end
    return nil
end

local function bytes_uuid_str(b16)
    if not b16 or #b16 < 16 then return "<invalid-uuid>" end
    local t = { b16:byte(1, 16) }
    return string.format(
        "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
        t[1], t[2], t[3], t[4], t[5], t[6], t[7], t[8],
        t[9], t[10], t[11], t[12], t[13], t[14], t[15], t[16]
    )
end

local function xpc_type_from_raw(raw)
    local code = math.floor((raw - 0x1000) / 0x1000)
    if code == 0x00 then return "null" end
    if code == 0x01 then return "bool" end
    if code == 0x02 then return "int64" end
    if code == 0x03 then return "uint64" end
    if code == 0x04 then return "double" end
    if code == 0x05 then return "ptr" end
    if code == 0x06 then return "date" end
    if code == 0x07 then return "data" end
    if code == 0x08 then return "string" end
    if code == 0x09 then return "uuid" end
    if code == 0x0A then return "file" end
    if code == 0x0B then return "shmem" end
    if code == 0x0C then return "mach_send" end
    if code == 0x0D then return "array" end
    if code == 0x0E then return "dict" end
    return "unknown"
end

local function parse_xpc_object(st, ps, depth)
    if depth > ps.max_depth then
        return nil, "max depth reached"
    end
    ps.nodes = ps.nodes + 1
    if ps.nodes > ps.max_nodes then
        return nil, "max nodes reached"
    end

    local raw = stream_read_u32_le(st)
    if raw == nil then
        return nil, "unexpected EOF reading object header"
    end
    local typ = xpc_type_from_raw(raw)
    local obj = { type = typ, raw = raw }

    if typ == "null" then
        return obj
    elseif typ == "bool" then
        local v = stream_read_u32_le(st)
        if v == nil then return nil, "unexpected EOF reading bool" end
        obj.value = (v ~= 0)
        return obj
    elseif typ == "int64" then
        local lo, hi = stream_read_u64_parts(st)
        if lo == nil then return nil, "unexpected EOF reading int64" end
        obj.lo = lo
        obj.hi = hi
        obj.hex = u64_hex(hi, lo)
        return obj
    elseif typ == "uint64" then
        local lo, hi = stream_read_u64_parts(st)
        if lo == nil then return nil, "unexpected EOF reading uint64" end
        obj.lo = lo
        obj.hi = hi
        obj.hex = u64_hex(hi, lo)
        obj.safe = u64_to_number_safe(hi, lo)
        return obj
    elseif typ == "double" then
        local raw8 = stream_read_bytes(st, 8)
        if not raw8 then return nil, "unexpected EOF reading double" end
        obj.raw_hex = bytes_to_hex(raw8)
        if string.unpack then
            local ok, d = pcall(string.unpack, "<d", raw8)
            if ok then obj.value = d end
        end
        return obj
    elseif typ == "date" then
        local lo, hi = stream_read_u64_parts(st)
        if lo == nil then return nil, "unexpected EOF reading date" end
        obj.lo = lo
        obj.hi = hi
        obj.hex = u64_hex(hi, lo)
        obj.safe = u64_to_number_safe(hi, lo)
        return obj
    elseif typ == "data" then
        local n = stream_read_u32_le(st)
        if n == nil then return nil, "unexpected EOF reading data length" end
        local b = stream_read_bytes(st, n)
        if not b then return nil, "unexpected EOF reading data bytes" end
        obj.length = n
        obj.bytes = b
        return obj
    elseif typ == "string" then
        local n = stream_read_u32_le(st)
        if n == nil then return nil, "unexpected EOF reading string length" end
        local b = stream_read_bytes(st, n)
        if not b then return nil, "unexpected EOF reading string bytes" end
        if n > 0 and b:byte(#b) == 0 then
            b = b:sub(1, #b - 1)
        end
        obj.length = n
        obj.value = b
        return obj
    elseif typ == "uuid" then
        local b = stream_read_bytes(st, 16)
        if not b then return nil, "unexpected EOF reading uuid" end
        obj.value = bytes_uuid_str(b)
        return obj
    elseif typ == "array" then
        local total_bytes = stream_read_u32_le(st)
        local num_items = stream_read_u32_le(st)
        if total_bytes == nil or num_items == nil then
            return nil, "unexpected EOF reading array header"
        end
        if total_bytes < 4 then
            return nil, "invalid array total_bytes"
        end
        local end_off = stream_tell(st) + (total_bytes - 4)
        if end_off > st.len then end_off = st.len end
        obj.num_items = num_items
        obj.items = {}
        for i = 1, num_items do
            if stream_tell(st) > end_off then break end
            stream_align4(st)
            local it, err = parse_xpc_object(st, ps, depth + 1)
            if not it then return nil, err end
            obj.items[#obj.items + 1] = it
        end
        if stream_tell(st) < end_off then
            stream_seek(st, end_off)
        end
        return obj
    elseif typ == "dict" then
        local total_bytes = stream_read_u32_le(st)
        local num_entries = stream_read_u32_le(st)
        if total_bytes == nil or num_entries == nil then
            return nil, "unexpected EOF reading dict header"
        end
        if total_bytes < 4 then
            return nil, "invalid dict total_bytes"
        end
        local end_off = stream_tell(st) + (total_bytes - 4)
        if end_off > st.len then end_off = st.len end
        obj.num_entries = num_entries
        obj.entries = {}
        for _ = 1, num_entries do
            if stream_tell(st) >= end_off then break end
            local key_bytes = {}
            while true do
                local c = stream_read_u8(st)
                if c == nil then return nil, "unexpected EOF reading dict key" end
                if c == 0 then break end
                key_bytes[#key_bytes + 1] = string.char(c)
            end
            local key = table.concat(key_bytes)
            stream_align4(st)
            local v, err = parse_xpc_object(st, ps, depth + 1)
            if not v then return nil, err end
            obj.entries[#obj.entries + 1] = { key = key, value = v }
            stream_align4(st)
        end
        if stream_tell(st) < end_off then
            stream_seek(st, end_off)
        end
        return obj
    else
        -- Unknown/unimplemented type: keep raw header only.
        return obj
    end
end

local function decode_xpc_serialized_bin(bin)
    if not bin or #bin == 0 then
        return nil, "empty serialized blob"
    end

    local function u32_at(s, off1)
        if #s < off1 + 3 then return nil end
        local b1, b2, b3, b4 = s:byte(off1, off1 + 3)
        return b1 + b2 * 0x100 + b3 * 0x10000 + b4 * 0x1000000
    end

    local start_off = 0
    local mode = "raw_object"
    local m0 = u32_at(bin, 1)
    local m1 = u32_at(bin, 5)

    if m0 == 0x42133742 and m1 == 5 then
        start_off = 8
        mode = "libxpc_serialized_header"
    elseif m0 == 0x40585043 and m1 == 5 then
        start_off = 8
        mode = "cpx_header"
    else
        local limit = #bin - 7
        if limit > 512 then limit = 512 end
        for i = 1, limit do
            local mm0 = u32_at(bin, i)
            local mm1 = u32_at(bin, i + 4)
            if mm0 == 0x40585043 and mm1 == 5 then
                start_off = (i - 1) + 8
                mode = "embedded_cpx_header"
                break
            end
        end
    end

    local st = stream_new(bin, start_off)
    local ps = { nodes = 0, max_nodes = 4096, max_depth = 64 }
    local obj, err = parse_xpc_object(st, ps, 0)
    if not obj then
        return nil, err
    end
    return {
        mode = mode,
        root = obj,
        consumed = st.ofs - start_off,
        remaining = stream_remaining(st),
        nodes = ps.nodes,
    }
end

local function bplist_u_be(bin, off0, nbytes)
    if nbytes <= 0 then return 0 end
    if off0 < 0 or off0 + nbytes > #bin then return nil end
    local v = 0
    for i = 0, nbytes - 1 do
        v = (v * 256) + (bin:byte(off0 + i + 1) or 0)
    end
    return v
end

local function bplist_u_le(bin, off0, nbytes)
    if nbytes <= 0 then return 0 end
    if off0 < 0 or off0 + nbytes > #bin then return nil end
    local v = 0
    local mul = 1
    for i = 0, nbytes - 1 do
        v = v + ((bin:byte(off0 + i + 1) or 0) * mul)
        mul = mul * 256
    end
    return v
end

local function bplist_signed_from_unsigned(u, nbytes)
    if not u or nbytes <= 0 then return nil end
    local bits = nbytes * 8
    if bits > 52 then return nil end
    local sign_bit = 2 ^ (bits - 1)
    local full = 2 ^ bits
    if u >= sign_bit then
        return u - full
    end
    return u
end

local function utf16be_to_utf8(bin)
    if not bin or #bin == 0 then return "" end
    local out = {}
    local i = 1
    while i + 1 <= #bin do
        local c = (bin:byte(i) * 256) + bin:byte(i + 1)
        if c < 0x80 then
            out[#out + 1] = string.char(c)
        elseif c < 0x800 then
            out[#out + 1] = string.char(0xC0 + math.floor(c / 64))
            out[#out + 1] = string.char(0x80 + (c % 64))
        else
            out[#out + 1] = string.char(0xE0 + math.floor(c / 4096))
            out[#out + 1] = string.char(0x80 + (math.floor(c / 64) % 64))
            out[#out + 1] = string.char(0x80 + (c % 64))
        end
        i = i + 2
    end
    return table.concat(out)
end

local function utf16le_to_utf8(bin)
    if not bin or #bin == 0 then return "" end
    local out = {}
    local i = 1
    while i + 1 <= #bin do
        local c = bin:byte(i) + (bin:byte(i + 1) * 256)
        if c < 0x80 then
            out[#out + 1] = string.char(c)
        elseif c < 0x800 then
            out[#out + 1] = string.char(0xC0 + math.floor(c / 64))
            out[#out + 1] = string.char(0x80 + (c % 64))
        else
            out[#out + 1] = string.char(0xE0 + math.floor(c / 4096))
            out[#out + 1] = string.char(0x80 + (math.floor(c / 64) % 64))
            out[#out + 1] = string.char(0x80 + (c % 64))
        end
        i = i + 2
    end
    return table.concat(out)
end

local function bplist17_parse_int_marker(bin, off0)
    if off0 < 0 or off0 >= #bin then return nil, nil, "offset out of range" end
    local marker = bin:byte(off0 + 1)
    if not marker then return nil, nil, "EOF int marker" end
    if ((marker >> 4) ~= 0x1) then
        return nil, nil, string.format("expected int marker at 0x%x, got 0x%02x", off0, marker)
    end
    local width = marker & 0x0F
    if width ~= 1 and width ~= 2 and width ~= 4 and width ~= 8 then
        return nil, nil, "unsupported int width " .. tostring(width)
    end
    local val = bplist_u_le(bin, off0 + 1, width)
    if val == nil then return nil, nil, "truncated int payload" end
    return val, (off0 + width), nil
end

local function bplist17_parse_len(bin, marker_off, low_nibble)
    if low_nibble < 0xF then
        return low_nibble, marker_off + 1, nil
    end
    local length, int_last, err = bplist17_parse_int_marker(bin, marker_off + 1)
    if not length then return nil, nil, err end
    return length, int_last + 1, nil
end

local function bplist17_index_nodes(node, idx)
    if not node then return end
    if type(node.offset) == "number" then idx[node.offset] = node end
    if node.type == "array" and node.items then
        for _, it in ipairs(node.items) do
            bplist17_index_nodes(it, idx)
        end
    elseif node.type == "dict" and node.pairs then
        for _, kv in ipairs(node.pairs) do
            bplist17_index_nodes(kv.key, idx)
            bplist17_index_nodes(kv.value, idx)
        end
    end
end

local function bplist17_attach_ref_targets(node, idx)
    if not node then return end
    if node.type == "ref" then
        local target = idx[node.target]
        node.target_exists = (target ~= nil)
        if target and target.type then node.target_type = target.type end
    end
    if node.type == "array" and node.items then
        for _, it in ipairs(node.items) do
            bplist17_attach_ref_targets(it, idx)
        end
    elseif node.type == "dict" and node.pairs then
        for _, kv in ipairs(node.pairs) do
            bplist17_attach_ref_targets(kv.key, idx)
            bplist17_attach_ref_targets(kv.value, idx)
        end
    end
end

local function bplist17_parse_obj(bin, off0, depth, max_depth)
    if depth > max_depth then return nil, nil, "max depth reached" end
    if off0 < 0 or off0 >= #bin then return nil, nil, string.format("offset out of range: 0x%x", off0) end

    local marker = bin:byte(off0 + 1)
    local hi = marker >> 4
    local lo = marker & 0x0F
    local node = { offset = off0 }

    if hi == 0x1 then
        local width = lo
        if width ~= 1 and width ~= 2 and width ~= 4 and width ~= 8 then
            return nil, nil, string.format("unsupported int width %d at 0x%x", width, off0)
        end
        local v = bplist_u_le(bin, off0 + 1, width)
        if v == nil then return nil, nil, "truncated int" end
        node.type = "int"
        node.value = v
        node.width = width
        return node, off0 + width, nil
    end

    if hi == 0x2 then
        if lo == 0x2 then
            local raw = bin:sub(off0 + 2, off0 + 5)
            if #raw ~= 4 then return nil, nil, "truncated float32" end
            local ok, v = pcall(string.unpack, "<f", raw)
            node.type = "float32"
            node.value = ok and v or nil
            node.raw_hex = bytes_to_hex(raw)
            return node, off0 + 4, nil
        elseif lo == 0x3 then
            local raw = bin:sub(off0 + 2, off0 + 9)
            if #raw ~= 8 then return nil, nil, "truncated float64" end
            local ok, v = pcall(string.unpack, "<d", raw)
            node.type = "float64"
            node.value = ok and v or nil
            node.raw_hex = bytes_to_hex(raw)
            return node, off0 + 8, nil
        end
        return nil, nil, string.format("unsupported float marker 0x%02x at 0x%x", marker, off0)
    end

    if hi == 0x4 then
        local length, data_start, err = bplist17_parse_len(bin, off0, lo)
        if not length then return nil, nil, err end
        local data_end = data_start + length
        if data_end > #bin then return nil, nil, "truncated data blob" end
        local blob = bin:sub(data_start + 1, data_end)
        node.type = "data"
        node.length = length
        node.bytes = blob
        return node, data_end - 1, nil
    end

    if hi == 0x6 then
        local units, data_start, err = bplist17_parse_len(bin, off0, lo)
        if not units then return nil, nil, err end
        local byte_len = units * 2
        local data_end = data_start + byte_len
        if data_end > #bin then return nil, nil, "truncated utf16le string" end
        local raw = bin:sub(data_start + 1, data_end)
        node.type = "utf16"
        node.length_units = units
        node.value = utf16le_to_utf8(raw)
        return node, data_end - 1, nil
    end

    if hi == 0x7 then
        local length, data_start, err = bplist17_parse_len(bin, off0, lo)
        if not length then return nil, nil, err end
        local data_end = data_start + length
        if data_end > #bin then return nil, nil, "truncated ascii string" end
        local raw = bin:sub(data_start + 1, data_end)
        if length > 0 and raw:byte(#raw) == 0 then
            raw = raw:sub(1, #raw - 1)
        end
        node.type = "ascii"
        node.length = length
        node.value = raw
        return node, data_end - 1, nil
    end

    if hi == 0x8 then
        local width = lo
        if width ~= 1 and width ~= 2 and width ~= 4 and width ~= 8 then
            return nil, nil, string.format("unsupported ref width %d at 0x%x", width, off0)
        end
        local target = bplist_u_le(bin, off0 + 1, width)
        if target == nil then return nil, nil, "truncated reference" end
        node.type = "ref"
        node.width = width
        node.target = target
        return node, off0 + width, nil
    end

    if hi == 0xA then
        if off0 + 9 > #bin then return nil, nil, "truncated array header" end
        local end_off = bplist_u_le(bin, off0 + 1, 8)
        if not end_off or end_off >= #bin then
            return nil, nil, string.format("array end offset out of range: 0x%x", end_off or 0)
        end
        node.type = "array"
        node.count_hint = lo
        node.end_offset = end_off
        node.items = {}
        local cur = off0 + 9
        while cur <= end_off do
            local item, last, err = bplist17_parse_obj(bin, cur, depth + 1, max_depth)
            if not item then return nil, nil, err end
            node.items[#node.items + 1] = item
            cur = last + 1
        end
        return node, end_off, nil
    end

    if hi == 0xD then
        if off0 + 9 > #bin then return nil, nil, "truncated dict header" end
        local end_off = bplist_u_le(bin, off0 + 1, 8)
        if not end_off or end_off >= #bin then
            return nil, nil, string.format("dict end offset out of range: 0x%x", end_off or 0)
        end
        node.type = "dict"
        node.count_hint = lo
        node.end_offset = end_off
        node.pairs = {}
        local cur = off0 + 9
        while cur <= end_off do
            local k, klast, kerr = bplist17_parse_obj(bin, cur, depth + 1, max_depth)
            if not k then return nil, nil, kerr end
            cur = klast + 1
            if cur > end_off then return nil, nil, "dict ended between key and value" end
            local v, vlast, verr = bplist17_parse_obj(bin, cur, depth + 1, max_depth)
            if not v then return nil, nil, verr end
            cur = vlast + 1
            node.pairs[#node.pairs + 1] = { key = k, value = v }
        end
        return node, end_off, nil
    end

    if marker == 0xB0 then
        node.type = "bool"
        node.value = true
        return node, off0, nil
    end
    if marker == 0xC0 then
        node.type = "bool"
        node.value = false
        return node, off0, nil
    end
    if marker == 0xE0 then
        node.type = "null"
        node.value = nil
        return node, off0, nil
    end
    if marker == 0xF8 then
        local value = bplist_u_le(bin, off0 + 1, 8)
        if value == nil then return nil, nil, "truncated unsigned 64 marker" end
        node.type = "u64"
        node.value = value
        return node, off0 + 8, nil
    end

    return nil, nil, string.format("unknown marker 0x%02x at 0x%x", marker, off0)
end

local function decode_bplist17(bin)
    if not bin or #bin < 9 then return nil, "bplist17 too short" end
    if bin:sub(1, 8) ~= "bplist17" then return nil, "missing bplist17 header" end

    local top, last, err = bplist17_parse_obj(bin, 8, 0, 256)
    if not top then return nil, err end

    local idx = {}
    bplist17_index_nodes(top, idx)
    bplist17_attach_ref_targets(top, idx)

    local node_count = 0
    for _ in pairs(idx) do node_count = node_count + 1 end

    return {
        dialect = "bplist17",
        version = "17",
        top = top,
        top_object = 8,
        nodes = node_count,
        consumed_bytes = (last - 8 + 1),
        remaining_bytes = #bin - (last + 1),
    }
end

local function bplist_parse_length(parser, info, cursor0)
    if info < 0xF then
        return info, cursor0
    end
    if cursor0 >= parser.len then return nil, nil, "EOF while reading length marker" end
    local m2 = parser.bin:byte(cursor0 + 1)
    local t2 = m2 >> 4
    local n2 = m2 & 0x0F
    if t2 ~= 0x1 then
        return nil, nil, "extended length marker is not int"
    end
    local int_bytes = 2 ^ n2
    local v = bplist_u_be(parser.bin, cursor0 + 1, int_bytes)
    if not v then return nil, nil, "EOF while reading extended length" end
    return v, cursor0 + 1 + int_bytes
end

local function bplist_parse_obj_id(parser, obj_id, depth)
    if obj_id < 0 or obj_id >= parser.num_objects then
        return nil, "object id out of range: " .. tostring(obj_id)
    end
    if parser.cache[obj_id] then return parser.cache[obj_id] end
    if parser.visiting[obj_id] then return nil, "cycle detected at object id " .. tostring(obj_id) end
    if depth > parser.max_depth then return nil, "bplist max depth reached" end

    parser.nodes = parser.nodes + 1
    if parser.nodes > parser.max_nodes then
        return nil, "bplist max nodes reached"
    end

    local off0 = parser.offsets[obj_id]
    if not off0 then return nil, "missing offset for object id " .. tostring(obj_id) end
    if off0 < 0 or off0 >= parser.len then return nil, "object offset out of range" end

    parser.visiting[obj_id] = true
    local marker = parser.bin:byte(off0 + 1)
    local otype = marker >> 4
    local info = marker & 0x0F
    local cursor = off0 + 1
    local obj = { id = obj_id, off = off0 }

    if otype == 0x0 then
        if info == 0x0 then
            obj.type = "null"
        elseif info == 0x8 then
            obj.type = "bool"
            obj.value = false
        elseif info == 0x9 then
            obj.type = "bool"
            obj.value = true
        elseif info == 0xF then
            obj.type = "fill"
        else
            obj.type = "simple"
            obj.value = info
        end
    elseif otype == 0x1 then
        local nbytes = 2 ^ info
        local u = bplist_u_be(parser.bin, cursor, nbytes)
        if not u then parser.visiting[obj_id] = nil; return nil, "EOF int object" end
        obj.type = "int"
        obj.nbytes = nbytes
        obj.unsigned = u
        obj.signed = bplist_signed_from_unsigned(u, nbytes)
        obj.hex = string.format("0x%s", bytes_to_hex(parser.bin:sub(cursor + 1, cursor + nbytes)))
    elseif otype == 0x2 then
        local nbytes = 2 ^ info
        local raw = parser.bin:sub(cursor + 1, cursor + nbytes)
        if #raw ~= nbytes then parser.visiting[obj_id] = nil; return nil, "EOF real object" end
        obj.type = "real"
        obj.nbytes = nbytes
        obj.raw_hex = bytes_to_hex(raw)
        if string.unpack and (nbytes == 4 or nbytes == 8) then
            local ok, v = pcall(string.unpack, (nbytes == 4) and ">f" or ">d", raw)
            if ok then obj.value = v end
        end
    elseif otype == 0x3 then
        local raw = parser.bin:sub(cursor + 1, cursor + 8)
        if #raw ~= 8 then parser.visiting[obj_id] = nil; return nil, "EOF date object" end
        obj.type = "date"
        obj.raw_hex = bytes_to_hex(raw)
        if string.unpack then
            local ok, sec = pcall(string.unpack, ">d", raw)
            if ok then
                obj.seconds_since_2001 = sec
                obj.unix_epoch = sec + 978307200.0
            end
        end
    elseif otype == 0x4 then
        local n, next_cursor, err = bplist_parse_length(parser, info, cursor)
        if not n then parser.visiting[obj_id] = nil; return nil, err end
        local raw = parser.bin:sub(next_cursor + 1, next_cursor + n)
        if #raw ~= n then parser.visiting[obj_id] = nil; return nil, "EOF data object" end
        obj.type = "data"
        obj.length = n
        obj.bytes = raw
    elseif otype == 0x5 then
        local n, next_cursor, err = bplist_parse_length(parser, info, cursor)
        if not n then parser.visiting[obj_id] = nil; return nil, err end
        local raw = parser.bin:sub(next_cursor + 1, next_cursor + n)
        if #raw ~= n then parser.visiting[obj_id] = nil; return nil, "EOF ascii string" end
        obj.type = "string"
        obj.encoding = "ascii"
        obj.value = raw
    elseif otype == 0x6 then
        local n, next_cursor, err = bplist_parse_length(parser, info, cursor)
        if not n then parser.visiting[obj_id] = nil; return nil, err end
        local raw = parser.bin:sub(next_cursor + 1, next_cursor + (n * 2))
        if #raw ~= (n * 2) then parser.visiting[obj_id] = nil; return nil, "EOF utf16 string" end
        obj.type = "string"
        obj.encoding = "utf16be"
        obj.value = utf16be_to_utf8(raw)
    elseif otype == 0x7 then
        local n, next_cursor, err = bplist_parse_length(parser, info, cursor)
        if not n then parser.visiting[obj_id] = nil; return nil, err end
        local raw = parser.bin:sub(next_cursor + 1, next_cursor + n)
        if #raw ~= n then parser.visiting[obj_id] = nil; return nil, "EOF utf8 string" end
        obj.type = "string"
        obj.encoding = "utf8"
        obj.value = raw
    elseif otype == 0x8 then
        local nbytes = info + 1
        local u = bplist_u_be(parser.bin, cursor, nbytes)
        if not u then parser.visiting[obj_id] = nil; return nil, "EOF uid" end
        obj.type = "uid"
        obj.nbytes = nbytes
        obj.value = u
    elseif otype == 0xA or otype == 0xB or otype == 0xC then
        local n, next_cursor, err = bplist_parse_length(parser, info, cursor)
        if not n then parser.visiting[obj_id] = nil; return nil, err end
        local kind = (otype == 0xA) and "array" or ((otype == 0xB) and "ordset" or "set")
        obj.type = kind
        obj.items = {}
        local ref_pos = next_cursor
        for _ = 1, n do
            local rid = bplist_u_be(parser.bin, ref_pos, parser.object_ref_size)
            if rid == nil then parser.visiting[obj_id] = nil; return nil, "EOF " .. kind .. " refs" end
            ref_pos = ref_pos + parser.object_ref_size
            local v, verr = bplist_parse_obj_id(parser, rid, depth + 1)
            if not v then parser.visiting[obj_id] = nil; return nil, verr end
            obj.items[#obj.items + 1] = v
        end
    elseif otype == 0xD then
        local n, next_cursor, err = bplist_parse_length(parser, info, cursor)
        if not n then parser.visiting[obj_id] = nil; return nil, err end
        obj.type = "dict"
        obj.entries = {}
        local key_ref_pos = next_cursor
        local val_ref_pos = next_cursor + (n * parser.object_ref_size)
        for _ = 1, n do
            local kid = bplist_u_be(parser.bin, key_ref_pos, parser.object_ref_size)
            local vid = bplist_u_be(parser.bin, val_ref_pos, parser.object_ref_size)
            if kid == nil or vid == nil then parser.visiting[obj_id] = nil; return nil, "EOF dict refs" end
            key_ref_pos = key_ref_pos + parser.object_ref_size
            val_ref_pos = val_ref_pos + parser.object_ref_size
            local kobj, kerr = bplist_parse_obj_id(parser, kid, depth + 1)
            if not kobj then parser.visiting[obj_id] = nil; return nil, kerr end
            local vobj, verr = bplist_parse_obj_id(parser, vid, depth + 1)
            if not vobj then parser.visiting[obj_id] = nil; return nil, verr end
            obj.entries[#obj.entries + 1] = { key = kobj, value = vobj }
        end
    else
        obj.type = "unknown"
        obj.marker = marker
    end

    parser.cache[obj_id] = obj
    parser.visiting[obj_id] = nil
    return obj
end

local function decode_bplist00(bin)
    if not bin or #bin < 40 then return nil, "bplist too short" end
    if #bin < 8 or bin:sub(1, 6) ~= "bplist" then
        return nil, "missing bplist magic"
    end
    local version = bin:sub(7, 8)
    if not version:match("^%d%d$") then
        return nil, "unsupported bplist version tag: " .. tostring(version)
    end

    local trailer_off = #bin - 32
    local offset_int_size = bin:byte(trailer_off + 7)
    local object_ref_size = bin:byte(trailer_off + 8)
    local num_objects = bplist_u_be(bin, trailer_off + 8, 8)
    local top_object = bplist_u_be(bin, trailer_off + 16, 8)
    local offset_table_off = bplist_u_be(bin, trailer_off + 24, 8)

    if not offset_int_size or offset_int_size <= 0 then return nil, "invalid offset_int_size" end
    if not object_ref_size or object_ref_size <= 0 then return nil, "invalid object_ref_size" end
    if not num_objects or num_objects <= 0 then return nil, "invalid num_objects" end
    if num_objects > 65536 then return nil, "num_objects too large" end
    if not top_object or top_object < 0 or top_object >= num_objects then return nil, "invalid top_object" end
    if not offset_table_off or offset_table_off < 0 or offset_table_off >= #bin then
        return nil, "invalid offset_table_offset"
    end

    local need = offset_table_off + (num_objects * offset_int_size)
    if need > #bin then
        return nil, "offset table exceeds buffer"
    end

    local offsets = {}
    local p = offset_table_off
    for i = 0, num_objects - 1 do
        local off = bplist_u_be(bin, p, offset_int_size)
        if off == nil then return nil, "bad offset table entry" end
        if off < 0 or off >= #bin then return nil, "object offset out of range" end
        offsets[i] = off
        p = p + offset_int_size
    end

    local parser = {
        bin = bin,
        len = #bin,
        offsets = offsets,
        num_objects = num_objects,
        object_ref_size = object_ref_size,
        cache = {},
        visiting = {},
        nodes = 0,
        max_nodes = 8192,
        max_depth = 128,
    }

    local top, err = bplist_parse_obj_id(parser, top_object, 0)
    if not top then return nil, err end
    return {
        dialect = "bplist00",
        version = version,
        top = top,
        num_objects = num_objects,
        top_object = top_object,
        offset_int_size = offset_int_size,
        object_ref_size = object_ref_size,
        nodes = parser.nodes,
    }
end

local function decode_bplist(bin)
    if not bin or #bin < 8 or bin:sub(1, 6) ~= "bplist" then
        return nil, "missing bplist magic"
    end
    local version = bin:sub(7, 8)
    if version == "00" then
        return decode_bplist00(bin)
    elseif version == "17" then
        return decode_bplist17(bin)
    end
    return nil, "unsupported bplist version: " .. tostring(version)
end

local render_bplist_obj
local render_xpc_obj
local maybe_decode_embedded_blob

local function bplist_key_to_string(kobj)
    if not kobj then return "<nil-key>" end
    if kobj.type == "string" then
        return safe_ascii(kobj.value, 200)
    elseif kobj.type == "ascii" or kobj.type == "utf16" then
        return safe_ascii(kobj.value, 200)
    elseif kobj.type == "int" then
        if kobj.value ~= nil then return tostring(kobj.value) end
        if kobj.signed ~= nil then return tostring(kobj.signed) end
        return tostring(kobj.unsigned or "<int>")
    elseif kobj.type == "u64" then
        return tostring(kobj.value or "<u64>")
    elseif kobj.type == "uid" then
        return "uid(" .. tostring(kobj.value or "?") .. ")"
    elseif kobj.type == "ref" then
        return string.format("ref(0x%x)", kobj.target or 0)
    end
    return "<key type=" .. tostring(kobj.type) .. ">"
end

render_bplist_obj = function(tree, tvb, name, obj, depth)
    if not obj then
        tree:add(tvb(0, 0), name .. ": <nil>")
        return
    end
    if depth > 128 then
        tree:add(tvb(0, 0), name .. ": <depth-limit>")
        return
    end

    local typ = obj.type or "unknown"
    if typ == "null" then
        tree:add(tvb(0, 0), name .. ": null")
    elseif typ == "bool" then
        tree:add(tvb(0, 0), name .. ": " .. tostring(obj.value))
    elseif typ == "int" then
        if obj.value ~= nil then
            tree:add(tvb(0, 0), name .. ": int " .. tostring(obj.value))
        elseif obj.signed ~= nil then
            tree:add(tvb(0, 0), name .. ": int " .. tostring(obj.signed) .. " (" .. tostring(obj.hex or "") .. ")")
        else
            tree:add(tvb(0, 0), name .. ": int " .. tostring(obj.unsigned or "") .. " (" .. tostring(obj.hex or "") .. ")")
        end
    elseif typ == "u64" then
        tree:add(tvb(0, 0), name .. ": u64 " .. tostring(obj.value or ""))
    elseif typ == "float32" or typ == "float64" then
        if obj.value ~= nil then
            tree:add(tvb(0, 0), name .. ": " .. typ .. " " .. tostring(obj.value))
        else
            tree:add(tvb(0, 0), name .. ": " .. typ .. " raw=0x" .. tostring(obj.raw_hex or ""))
        end
    elseif typ == "ascii" or typ == "utf16" then
        tree:add(tvb(0, 0), name .. ': "' .. safe_ascii(obj.value, 256) .. '"')
    elseif typ == "ref" then
        local label = string.format("%s: ref(0x%x)", name, obj.target or 0)
        local rt = tree:add(tvb(0, 0), label)
        if obj.target_type then
            rt:add(tvb(0, 0), "target_type: " .. tostring(obj.target_type))
        end
        rt:add(tvb(0, 0), "target_exists: " .. tostring(obj.target_exists == true))
    elseif typ == "string" then
        tree:add(tvb(0, 0), name .. ': "' .. safe_ascii(obj.value, 256) .. '"')
    elseif typ == "real" then
        if obj.value ~= nil then
            tree:add(tvb(0, 0), name .. ": real " .. tostring(obj.value))
        else
            tree:add(tvb(0, 0), name .. ": real raw=0x" .. tostring(obj.raw_hex or ""))
        end
    elseif typ == "date" then
        if obj.unix_epoch ~= nil then
            tree:add(tvb(0, 0), name .. ": date unix=" .. tostring(obj.unix_epoch))
        else
            tree:add(tvb(0, 0), name .. ": date raw=0x" .. tostring(obj.raw_hex or ""))
        end
    elseif typ == "uid" then
        tree:add(tvb(0, 0), name .. ": uid(" .. tostring(obj.value or "?") .. ")")
    elseif typ == "data" then
        local st = tree:add(tvb(0, 0), string.format("%s: data[%d]", name, obj.length or 0))
        if obj.bytes then
            st:add(tvb(0, 0), "hex_preview: " .. bytes_to_hex(obj.bytes, 64))
            maybe_decode_embedded_blob(st, tvb, obj.bytes, depth + 1)

            -- add full hexdump view (no truncation)
            local raw = obj.bytes
            local dump = {}
            local shown = #raw
            for i = 1, shown, 16 do
                local chunk = raw:sub(i, i + 15)
                local hex_parts = {}
                local ascii_parts = {}
                for j = 1, #chunk do
                    local byte = chunk:byte(j)
                    hex_parts[#hex_parts + 1] = string.format("%02x", byte)
                    if byte >= 32 and byte <= 126 then
                        ascii_parts[#ascii_parts + 1] = string.char(byte)
                    else
                        ascii_parts[#ascii_parts + 1] = "."
                    end
                end
                local offset = i - 1
                dump[#dump + 1] = string.format(
                    "%08x  %-48s  |%s|",
                    offset,
                    table.concat(hex_parts, " "),
                    table.concat(ascii_parts)
                )
            end
            st:add(tvb(0, 0), "hexdump"):set_text(table.concat(dump, "\n"))
        end
    elseif typ == "array" or typ == "set" or typ == "ordset" then
        local items = obj.items or {}
        local st = tree:add(tvb(0, 0), string.format("%s: %s[%d]", name, typ, #items))
        for i, it in ipairs(items) do
            render_bplist_obj(st, tvb, "[" .. tostring(i - 1) .. "]", it, depth + 1)
        end
    elseif typ == "dict" then
        local entries = obj.entries or obj.pairs or {}
        local st = tree:add(tvb(0, 0), string.format("%s: dict{%d}", name, #entries))
        for _, e in ipairs(entries) do
            local key = bplist_key_to_string(e.key)
            render_bplist_obj(st, tvb, key, e.value, depth + 1)
        end
    else
        tree:add(tvb(0, 0), name .. ": <" .. tostring(typ) .. ">")
    end
end

local function render_bplist_meta(p_tree, tvb, plist)
    p_tree:add(tvb(0, 0), "dialect: " .. tostring(plist.dialect or "unknown"))
    p_tree:add(tvb(0, 0), "version: " .. tostring(plist.version or "?"))
    p_tree:add(tvb(0, 0), "nodes: " .. tostring(plist.nodes or 0))
    if plist.dialect == "bplist00" then
        p_tree:add(tvb(0, 0), "num_objects: " .. tostring(plist.num_objects))
        p_tree:add(tvb(0, 0), "top_object: " .. tostring(plist.top_object))
        p_tree:add(tvb(0, 0), "offset_int_size: " .. tostring(plist.offset_int_size))
        p_tree:add(tvb(0, 0), "object_ref_size: " .. tostring(plist.object_ref_size))
    elseif plist.dialect == "bplist17" then
        p_tree:add(tvb(0, 0), "top_object: " .. tostring(plist.top_object))
        p_tree:add(tvb(0, 0), "consumed_bytes: " .. tostring(plist.consumed_bytes))
        p_tree:add(tvb(0, 0), "remaining_bytes: " .. tostring(plist.remaining_bytes))
    end
end

local function scan_known_magics(bin, max_hits)
    if not bin or #bin < 8 then return {} end
    local hits, seen = {}, {}
    local function add(off0, kind, name)
        local key = kind .. ":" .. tostring(off0)
        if seen[key] then return end
        seen[key] = true
        hits[#hits + 1] = { off = off0, kind = kind, name = name }
    end

    local pos = 1
    while #hits < max_hits do
        local s = bin:find("bplist", pos, true)
        if not s then break end
        if s + 7 <= #bin then
            local ver = bin:sub(s + 6, s + 7)
            if ver:match("^%d%d$") then
                add(s - 1, "bplist", "bplist" .. ver)
            end
        end
        pos = s + 1
    end

    local function scan_fixed(sig, kind, name)
        local p = 1
        while #hits < max_hits do
            local s = bin:find(sig, p, true)
            if not s then break end
            add(s - 1, kind, name)
            p = s + 1
        end
    end

    scan_fixed(string.char(0x42, 0x37, 0x13, 0x42, 0x05, 0x00, 0x00, 0x00), "xpc_serialized", "libxpc_v5")
    scan_fixed(string.char(0x43, 0x50, 0x58, 0x40, 0x05, 0x00, 0x00, 0x00), "xpc_serialized", "cpx_v5")

    table.sort(hits, function(a, b) return a.off < b.off end)
    return hits
end

maybe_decode_embedded_blob = function(tree, tvb, bin, depth)
    if not bin or #bin < 8 then return end
    if depth > 8 then
        tree:add(tvb(0, 0), "embedded_decode: <depth-limit>")
        return
    end

    local hits = scan_known_magics(bin, 8)
    if #hits == 0 then return end

    local scan_tree = tree:add(tvb(0, 0), string.format("embedded_decode_scan: hits=%d", #hits))
    local success = 0
    local success_at_zero = false
    local function try_hit(h)
        local sub = bin:sub(h.off + 1)
        local at = string.format("at+%d", h.off)
        if h.kind == "bplist" then
            local plist, err = decode_bplist(sub)
            if plist then
                success = success + 1
                if h.off == 0 then success_at_zero = true end
                local p_tree = scan_tree:add(tvb(0, 0), string.format("%s: %s", at, h.name))
                render_bplist_meta(p_tree, tvb, plist)
                render_bplist_obj(p_tree, tvb, "root", plist.top, depth + 1)
            elseif h.off == 0 then
                scan_tree:add(tvb(0, 0), string.format("%s: %s decode_error: %s", at, h.name, tostring(err)))
            end
        elseif h.kind == "xpc_serialized" then
            local decoded, err = decode_xpc_serialized_bin(sub)
            if decoded then
                success = success + 1
                if h.off == 0 then success_at_zero = true end
                local x_tree = scan_tree:add(tvb(0, 0), string.format("%s: %s", at, h.name))
                x_tree:add(tvb(0, 0), "decode_mode: " .. tostring(decoded.mode))
                x_tree:add(tvb(0, 0), "nodes: " .. tostring(decoded.nodes))
                x_tree:add(tvb(0, 0), "consumed_bytes: " .. tostring(decoded.consumed))
                if decoded.remaining and decoded.remaining > 0 then
                    x_tree:add(tvb(0, 0), "remaining_bytes: " .. tostring(decoded.remaining))
                end
                render_xpc_obj(x_tree, tvb, "root", decoded.root, depth + 1)
            elseif h.off == 0 then
                scan_tree:add(tvb(0, 0), string.format("%s: %s decode_error: %s", at, h.name, tostring(err)))
            end
        end
    end

    for _, h in ipairs(hits) do
        if h.off == 0 then
            try_hit(h)
        end
    end
    if not success_at_zero then
        for _, h in ipairs(hits) do
            if h.off ~= 0 then
                try_hit(h)
            end
        end
    end

    if success == 0 then
        scan_tree:add(tvb(0, 0), "no decodable known blobs")
    end
end

render_xpc_obj = function(tree, tvb, name, obj, depth)
    if not obj then
        tree:add(tvb(0, 0), name .. ": <nil>")
        return
    end
    if depth > 64 then
        tree:add(tvb(0, 0), name .. ": <depth-limit>")
        return
    end

    local typ = obj.type or "unknown"
    if typ == "null" then
        tree:add(tvb(0, 0), name .. ": null")
    elseif typ == "bool" then
        tree:add(tvb(0, 0), name .. ": " .. tostring(obj.value))
    elseif typ == "int64" then
        tree:add(tvb(0, 0), name .. ": int64 " .. (obj.hex or "<invalid>"))
    elseif typ == "uint64" then
        if obj.safe ~= nil then
            tree:add(tvb(0, 0), name .. ": uint64 " .. tostring(math.floor(obj.safe)) .. " (" .. (obj.hex or "") .. ")")
        else
            tree:add(tvb(0, 0), name .. ": uint64 " .. (obj.hex or "<invalid>"))
        end
    elseif typ == "double" then
        if obj.value ~= nil then
            tree:add(tvb(0, 0), name .. ": double " .. tostring(obj.value))
        else
            tree:add(tvb(0, 0), name .. ": double raw=0x" .. (obj.raw_hex or ""))
        end
    elseif typ == "date" then
        if obj.safe ~= nil then
            tree:add(tvb(0, 0), name .. ": date(" .. tostring(math.floor(obj.safe)) .. ")")
        else
            tree:add(tvb(0, 0), name .. ": date(" .. (obj.hex or "<invalid>") .. ")")
        end
    elseif typ == "data" then
        local label = string.format("%s: data[%d]", name, obj.length or 0)
        local st = tree:add(tvb(0, 0), label)
        if obj.bytes then
            st:add(tvb(0, 0), "hex_preview: " .. bytes_to_hex(obj.bytes, 64))
            maybe_decode_embedded_blob(st, tvb, obj.bytes, depth + 1)

            local raw = obj.bytes
            local dump = {}
            local shown = #raw
            for i = 1, shown, 16 do
                local chunk = raw:sub(i, i + 15)
                local hex_parts = {}
                local ascii_parts = {}
                for j = 1, #chunk do
                    local byte = chunk:byte(j)
                    hex_parts[#hex_parts + 1] = string.format("%02x", byte)
                    if byte >= 32 and byte <= 126 then
                        ascii_parts[#ascii_parts + 1] = string.char(byte)
                    else
                        ascii_parts[#ascii_parts + 1] = "."
                    end
                end
                local offset = i - 1
                dump[#dump + 1] = string.format(
                    "%08x  %-48s  |%s|",
                    offset,
                    table.concat(hex_parts, " "),
                    table.concat(ascii_parts)
                )
            end
            local hexdump_node = st:add(tvb(0, 0), "hexdump")
            hexdump_node:set_text(table.concat(dump, "\n"))
        end
    elseif typ == "string" then
        tree:add(tvb(0, 0), name .. ': "' .. safe_ascii(obj.value, 256) .. '"')
    elseif typ == "uuid" then
        tree:add(tvb(0, 0), name .. ": uuid(" .. tostring(obj.value or "") .. ")")
    elseif typ == "array" then
        local items = obj.items or {}
        local st = tree:add(tvb(0, 0), string.format("%s: array[%d]", name, #items))
        for i, it in ipairs(items) do
            render_xpc_obj(st, tvb, "[" .. tostring(i - 1) .. "]", it, depth + 1)
        end
    elseif typ == "dict" then
        local entries = obj.entries or {}
        local st = tree:add(tvb(0, 0), string.format("%s: dict{%d}", name, #entries))
        for _, e in ipairs(entries) do
            local key = e.key or "<key>"
            render_xpc_obj(st, tvb, key, e.value, depth + 1)
        end
    else
        tree:add(tvb(0, 0), string.format("%s: <unknown type raw=0x%08x>", name, obj.raw or 0))
    end
end

local function render_serialized_slot(tree, tvb, line, slot_name, slot)
    if not slot then
        slot = find_slot_wire_hex(line, slot_name)
    end
    if not slot or not slot.present then
        return nil
    end

    local st = tree:add(tvb(0, 0), "serialized." .. slot_name)
    st:add(tvb(0, 0), "format: " .. tostring(slot.format_name or "unknown"))
    if slot.original_len then st:add(tvb(0, 0), "original_len: " .. tostring(slot.original_len)) end
    if slot.stored_len then st:add(tvb(0, 0), "stored_len: " .. tostring(slot.stored_len)) end
    st:add(tvb(0, 0), "truncated: " .. tostring(slot.truncated))

    if not slot.wire_hex then
        st:add(tvb(0, 0), "decode_error: missing wire_hex")
        return slot
    end

    local bin, hex_err = hex_to_bin(slot.wire_hex)
    if not bin then
        st:add(tvb(0, 0), "decode_error: " .. tostring(hex_err))
        return slot
    end
    st:add(tvb(0, 0), "wire_hex_preview: " .. bytes_to_hex(bin, 64))

    local decoded, derr = decode_xpc_serialized_bin(bin)
    if not decoded then
        st:add(tvb(0, 0), "decode_error: " .. tostring(derr))
        return slot
    end

    st:add(tvb(0, 0), "decode_mode: " .. tostring(decoded.mode))
    st:add(tvb(0, 0), "nodes: " .. tostring(decoded.nodes))
    st:add(tvb(0, 0), "consumed_bytes: " .. tostring(decoded.consumed))
    if decoded.remaining and decoded.remaining > 0 then
        st:add(tvb(0, 0), "remaining_bytes: " .. tostring(decoded.remaining))
    end
    render_xpc_obj(st, tvb, "root", decoded.root, 0)
    return slot
end

local function read_frame(file, capture, frame)
    local st = capture.private_table
    if type(st) ~= "table" then
        st = {}
        capture.private_table = st
    end

    while true do
        local offset = file:seek()
        local line = file:read("*l")
        if not line then
            return false
        end
        if trim(line) ~= "" then
            frame.encap = XNIFF_ENCAP
            frame.captured_length = #line
            frame.original_length = #line
            frame.data = line

            local sec, nsec = update_time_from_line(line, st)
            local t = nstime_new(sec, nsec)
            if t then frame.time = t end
            return offset
        end
    end
end

local fh = FileHandler.new("XNIFF JSONL", "xniff_jsonl", "XNIFF JSON Lines capture reader", "rms")
fh.extensions = "jsonl;xniff.jsonl"

function fh.read_open(file, capture)
    local pos = file:seek()
    local accepted = false

    for _ = 1, 256 do
        local line = file:read("*l")
        if not line then break end
        local t = trim(line)
        if t ~= "" then
            if t:sub(1, 1) == "{" and t:find('"schema"%s*:%s*"xniff%.event%.v1"') then
                accepted = true
            end
            break
        end
    end

    file:seek("set", pos)
    if not accepted then
        return false
    end

    capture.encap = XNIFF_ENCAP
    if wtap_file_tsprec and wtap_file_tsprec.NSEC then
        capture.time_precision = wtap_file_tsprec.NSEC
    end
    capture.snapshot_length = 0
    capture.user_app = "xniff-jsonl.lua"
    capture.private_table = {
        base_mono = nil,
        base_epoch = nil,
    }
    return true
end

fh.read = read_frame

function fh.seek_read(file, capture, frame, offset)
    if not file:seek("set", offset) then
        return false
    end
    local rc = read_frame(file, capture, frame)
    if rc == false then return false end
    return true
end

register_filehandler(fh)

local function add_if_num(tree, tvb, field, n)
    if field ~= nil and n ~= nil then tree:add(field, tvb(0, 0), n) end
end

local function add_if_str(tree, tvb, field, s)
    if field ~= nil and s ~= nil and s ~= "" then tree:add(field, tvb(0, 0), s) end
end

local function add_if_bool(tree, tvb, field, v)
    if field ~= nil and v ~= nil then tree:add(field, tvb(0, 0), v) end
end

function xniff.dissector(tvb, pinfo, tree)
    local line = tvb(0, tvb:len()):string()
    pinfo.cols.protocol = "XNIFF"

    tree:add(xniff, tvb(), "XNIFF JSONL Event")

    local schema = find_json_string(line, "schema")
    local event_id = find_json_int(line, "event_id")
    local call_id = find_json_int(line, "call_id")
    local entry_event_id = find_json_int(line, "entry_event_id")
    local kind = find_json_string(line, "kind")
    local pid = find_json_int(line, "pid")
    local tid_low = find_json_int(line, "tid_low")
    local proc_name = find_json_string(line, "proc_name")
    local flow = find_json_string(line, "flow")
    local func_name = find_json_string(line, "func_name")
    local conn_seq = find_json_nullable_int(line, "conn_seq")
    local response_to = find_json_nullable_int(line, "response_to_event_id")
    local conn_pid = find_json_int(line, "conn_pid")
    local conn_name = find_json_string(line, "conn_name")
    local service_name = find_json_string(line, "service_name")
    local conn_ptr = find_json_string(line, "conn_ptr")
    local msg_ptr = find_json_string(line, "msg_ptr")

    add_if_str(tree, tvb, f_schema, schema)
    add_if_num(tree, tvb, f_event_id, event_id)
    add_if_num(tree, tvb, f_call_id, call_id)
    add_if_num(tree, tvb, f_entry_event_id, entry_event_id)
    add_if_str(tree, tvb, f_kind, kind)
    add_if_num(tree, tvb, f_pid, pid)
    add_if_num(tree, tvb, f_tid_low, tid_low)
    add_if_str(tree, tvb, f_proc_name, proc_name)
    add_if_str(tree, tvb, f_flow, flow)
    add_if_str(tree, tvb, f_func_name, func_name)
    add_if_num(tree, tvb, f_conn_seq, conn_seq)
    add_if_num(tree, tvb, f_response_to_event_id, response_to)
    add_if_num(tree, tvb, f_conn_pid, conn_pid)
    add_if_str(tree, tvb, f_conn_name, conn_name)
    add_if_str(tree, tvb, f_service_name, service_name)
    add_if_str(tree, tvb, f_conn_ptr, conn_ptr)
    add_if_str(tree, tvb, f_msg_ptr, msg_ptr)

    local has_msg, msg_len = slot_has_data(line, "message")
    local has_reply, reply_len = slot_has_data(line, "reply")
    local has_event, event_len = slot_has_data(line, "event")
    add_if_bool(tree, tvb, f_has_serialized_message, has_msg)
    add_if_bool(tree, tvb, f_has_serialized_reply, has_reply)
    add_if_bool(tree, tvb, f_has_serialized_event, has_event)
    add_if_num(tree, tvb, f_serialized_message_len, msg_len)
    add_if_num(tree, tvb, f_serialized_reply_len, reply_len)
    add_if_num(tree, tvb, f_serialized_event_len, event_len)

    if has_msg or has_reply or has_event then
        local ser_tree = tree:add(tvb(0, 0), "XPC Serialized Decode (xpcdesert-like)")
        render_serialized_slot(ser_tree, tvb, line, "message")
        render_serialized_slot(ser_tree, tvb, line, "reply")
        render_serialized_slot(ser_tree, tvb, line, "event")
    end

    local src = proc_name or (pid and tostring(pid)) or "?"
    local dst = conn_name or (conn_pid and tostring(conn_pid)) or "?"
    if flow == "recv" then
        local t = src
        src = dst
        dst = t
    end
    pinfo.cols.src = src
    pinfo.cols.dst = dst

    local info = {}
    if kind then table.insert(info, kind) end
    if event_id then table.insert(info, "event=" .. tostring(event_id)) end
    if call_id then table.insert(info, "call=" .. tostring(call_id)) end
    if flow then table.insert(info, "flow=" .. flow) end
    if func_name then table.insert(info, "func=" .. func_name) end
    if response_to then table.insert(info, "response_to=" .. tostring(response_to)) end
    pinfo.cols.info = table.concat(info, " ")

    if json_dissector then
        json_dissector:call(tvb, pinfo, tree)
    end
end

local wtap_encap = DissectorTable.get("wtap_encap")
if wtap_encap then
    wtap_encap:add(XNIFF_ENCAP, xniff)
end

-- Binary v2 capture support (.xniffbin / raw v2 stream)

local XNIFF_BIN_FILE_MAGIC = 0x584e4246
local XNIFF_BIN_FILE_VERSION = 2
local XNIFF_IPC_V2_VERSION = 1

local XNIFF_API_MACH_MSG = 1
local XNIFF_API_MACH_MSG2 = 2
local XNIFF_API_XPC_HL = 3
local XNIFF_API_DEBUG = 4

local XNIFF_DIR_ENTRY = 0
local XNIFF_DIR_EXIT = 1

local XNIFF_V2_SEC_MACH_HEADER_OPTIONS = 1
local XNIFF_V2_SEC_MACH_INLINE_BYTES = 2
local XNIFF_V2_SEC_MACH_TRAILER_BYTES = 3
local XNIFF_V2_SEC_MACH_DESC_META = 4
local XNIFF_V2_SEC_MACH_DESC_OOL_BYTES = 5
local XNIFF_V2_SEC_MACH_DESC_PORT_ARRAY = 6
local XNIFF_V2_SEC_XPC_SERIALIZED = 7
local XNIFF_V2_SEC_XPC_CONN_META = 8
local XNIFF_V2_SEC_HOOK_DIAG = 9
local XNIFF_V2_SEC_XPC_CALL_META = 10
local XNIFF_V2_SEC_BACKTRACE = 11
local XNIFF_V2_SEC_BACKTRACE_SYMBOLS = 12
local XNIFF_V2_SEC_CALL_ID = 13

local XNIFF_XPC_FUNC_CONNECTION_CREATE = 1
local XNIFF_XPC_FUNC_PIPE_ROUTINE = 2
local XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE = 3
local XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY = 4
local XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC = 5
local XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER = 6
local XNIFF_XPC_FUNC_CONNECTION_CHECK_IN = 7
local XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY = 8
local XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE = 9
local XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC = 10
local XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC = 11

local XNIFF_XPC_CONN_META_HAS_NAME_PUBLIC = (1 << 0)
local XNIFF_XPC_CONN_META_HAS_PID_PUBLIC = (1 << 2)

local MACH_SEND_MSG = 0x1
local MACH_RCV_MSG = 0x2

local g_bin_records_by_frame = {}

local function le_u16(s, off0)
    if not s or off0 < 0 or (off0 + 2) > #s then return nil end
    local b1, b2 = s:byte(off0 + 1, off0 + 2)
    return b1 + (b2 * 0x100)
end

local function le_u32(s, off0)
    if not s or off0 < 0 or (off0 + 4) > #s then return nil end
    local b1, b2, b3, b4 = s:byte(off0 + 1, off0 + 4)
    return b1 + (b2 * 0x100) + (b3 * 0x10000) + (b4 * 0x1000000)
end

local function le_i32(s, off0)
    local v = le_u32(s, off0)
    if v == nil then return nil end
    if v >= 0x80000000 then
        return v - 0x100000000
    end
    return v
end

local function le_u64_parts(s, off0)
    local lo = le_u32(s, off0)
    local hi = le_u32(s, off0 + 4)
    if lo == nil or hi == nil then return nil, nil end
    return lo, hi
end

local function le_u64_number(s, off0)
    local lo, hi = le_u64_parts(s, off0)
    if lo == nil then return nil end
    return (hi * 4294967296.0) + lo
end

local function le_u64_hex(s, off0)
    local lo, hi = le_u64_parts(s, off0)
    if lo == nil then return nil end
    return u64_hex(hi, lo), lo, hi
end

local function make_hexdump(raw)
    if not raw or #raw == 0 then return "" end
    local out = {}
    for i = 1, #raw, 16 do
        local chunk = raw:sub(i, i + 15)
        local hex_parts = {}
        local ascii_parts = {}
        for j = 1, #chunk do
            local byte = chunk:byte(j)
            hex_parts[#hex_parts + 1] = string.format("%02x", byte)
            if byte >= 32 and byte <= 126 then
                ascii_parts[#ascii_parts + 1] = string.char(byte)
            else
                ascii_parts[#ascii_parts + 1] = "."
            end
        end
        local offset = i - 1
        out[#out + 1] = string.format(
            "%08x  %-48s  |%s|",
            offset,
            table.concat(hex_parts, " "),
            table.concat(ascii_parts)
        )
    end
    return table.concat(out, "\n")
end

local function xpc_func_name(func)
    if func == XNIFF_XPC_FUNC_CONNECTION_CREATE then return "xpc_connection_create" end
    if func == XNIFF_XPC_FUNC_PIPE_ROUTINE then return "xpc_pipe_routine" end
    if func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE then return "xpc_connection_send_message" end
    if func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY then return "xpc_connection_send_message_with_reply" end
    if func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC then return "xpc_connection_send_message_with_reply_sync" end
    if func == XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER then return "_xpc_connection_call_event_handler" end
    if func == XNIFF_XPC_FUNC_CONNECTION_CHECK_IN then return "_xpc_connection_check_in" end
    if func == XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY then return "xpc_dictionary_send_reply" end
    if func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE then return "xpc_session_send_message" end
    if func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC then return "xpc_session_send_message_with_reply_async" end
    if func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC then return "xpc_session_send_message_with_reply_sync" end
    return "unknown"
end

local function xpc_flow(func)
    if func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE then return "send" end
    if func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY then return "send" end
    if func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC then return "send" end
    if func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE then return "send" end
    if func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC then return "send" end
    if func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC then return "send" end
    if func == XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER then return "recv" end
    if func == XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY then return "reply" end
    if func == XNIFF_XPC_FUNC_CONNECTION_CHECK_IN then return "rpc" end
    if func == XNIFF_XPC_FUNC_PIPE_ROUTINE then return "rpc" end
    if func == XNIFF_XPC_FUNC_CONNECTION_CREATE then return "meta" end
    return "unknown"
end

local function xpc_role(func, direction)
    if func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY or
       func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC or
       func == XNIFF_XPC_FUNC_PIPE_ROUTINE or
       func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC or
       func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC then
        return (direction == XNIFF_DIR_ENTRY) and "request" or "response"
    end
    if func == XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY then return "response" end
    if func == XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER then return "incoming" end
    if func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE or
       func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE then
        return "one-way"
    end
    return "metadata"
end

local function xpc_slot_name(slot)
    if slot == 1 then return "message" end
    if slot == 2 then return "reply" end
    if slot == 3 then return "event" end
    return "slot_" .. tostring(slot)
end

local function xpc_format_name(fmt)
    if fmt == 1 then return "libxpc_v5" end
    return tostring(fmt)
end

local function entry_kind_name(api, direction)
    if api == XNIFF_API_MACH_MSG then
        return (direction == XNIFF_DIR_ENTRY) and "entry" or "exit"
    elseif api == XNIFF_API_MACH_MSG2 then
        return (direction == XNIFF_DIR_ENTRY) and "entry2" or "exit2"
    elseif api == XNIFF_API_XPC_HL then
        return (direction == XNIFF_DIR_ENTRY) and "xpc_entry" or "xpc_exit"
    elseif api == XNIFF_API_DEBUG then
        return "debug_log"
    end
    return "unknown"
end

local function mach_function_name(fn)
    if fn == 1 then return "mach_msg_entry" end
    if fn == 2 then return "mach_msg_exit" end
    if fn == 3 then return "mach_msg2_entry" end
    if fn == 4 then return "mach_msg2_exit" end
    return "unknown"
end

local function xpc_string_field_names(kind, func)
    local names = { nil, nil, nil, nil }
    if func == XNIFF_XPC_FUNC_CONNECTION_CREATE then
        if kind == "xpc_entry" then
            names[1] = "target_service_name"
        else
            names[1] = "connection_name"
        end
    elseif func == XNIFF_XPC_FUNC_PIPE_ROUTINE then
        names[1] = "pipe_description"
        names[2] = "request_description"
        if kind == "xpc_exit" then names[3] = "reply_description" end
    elseif func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE or
           func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY or
           func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC then
        names[1] = "connection_name"
        names[2] = "message_description"
        names[3] = "connection_description"
        if kind == "xpc_exit" then names[4] = "reply_description" end
    elseif func == XNIFF_XPC_FUNC_CONNECTION_CHECK_IN then
        names[1] = "connection_name"
    end
    return names
end

local function xpc_arg_name(func, idx0)
    if func == XNIFF_XPC_FUNC_CONNECTION_CREATE then
        if idx0 == 0 then return "service_name_ptr" end
        if idx0 == 1 then return "target_queue_ptr" end
    elseif func == XNIFF_XPC_FUNC_PIPE_ROUTINE then
        if idx0 == 0 then return "pipe_ptr" end
        if idx0 == 1 then return "request_ptr_ptr" end
        if idx0 == 2 then return "reply_ptr_ptr" end
    elseif func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE then
        if idx0 == 0 then return "connection_ptr" end
        if idx0 == 1 then return "message_ptr" end
    elseif func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY then
        if idx0 == 0 then return "connection_ptr" end
        if idx0 == 1 then return "message_ptr" end
        if idx0 == 2 then return "reply_queue_ptr" end
        if idx0 == 3 then return "reply_handler_ptr" end
    elseif func == XNIFF_XPC_FUNC_CONNECTION_SEND_MESSAGE_WITH_REPLY_SYNC then
        if idx0 == 0 then return "connection_ptr" end
        if idx0 == 1 then return "message_ptr" end
    elseif func == XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER then
        if idx0 == 0 then return "connection_ptr" end
        if idx0 == 1 then return "event_ptr" end
    elseif func == XNIFF_XPC_FUNC_CONNECTION_CHECK_IN then
        if idx0 == 0 then return "connection_ptr" end
    elseif func == XNIFF_XPC_FUNC_DICTIONARY_SEND_REPLY then
        if idx0 == 0 then return "reply_ptr" end
    elseif func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE then
        if idx0 == 0 then return "session_ptr" end
        if idx0 == 1 then return "message_ptr" end
    elseif func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_ASYNC then
        if idx0 == 0 then return "session_ptr" end
        if idx0 == 1 then return "message_ptr" end
        if idx0 == 2 then return "reply_handler_ptr" end
    elseif func == XNIFF_XPC_FUNC_SESSION_SEND_MESSAGE_WITH_REPLY_SYNC then
        if idx0 == 0 then return "session_ptr" end
        if idx0 == 1 then return "message_ptr" end
        if idx0 == 2 then return "error_out_ptr" end
    end
    return nil
end

local function ts_from_ns_for_frame(ns, state)
    if not ns then return os.time(), 0 end
    if not state.base_mono_ns then
        state.base_mono_ns = ns
        state.base_epoch = os.time()
    end
    local delta = ns - state.base_mono_ns
    if delta < 0 then delta = 0 end
    local whole = math.floor(delta / 1000000000.0)
    local nsec = math.floor(delta - (whole * 1000000000.0) + 0.5)
    if nsec >= 1000000000 then
        whole = whole + 1
        nsec = nsec - 1000000000
    end
    return state.base_epoch + whole, nsec
end

local function parse_v2_record(entry)
    if not entry or #entry < 40 then
        return nil, "entry too short"
    end

    local entry_len = le_u32(entry, 0)
    local entry_type = le_u16(entry, 4)
    local version = le_u16(entry, 6)
    if not entry_len or not entry_type or not version then
        return nil, "invalid entry header"
    end
    if entry_len ~= #entry then
        return nil, "entry length mismatch"
    end
    if version ~= XNIFF_IPC_V2_VERSION then
        return nil, "unsupported v2 version"
    end

    local seq_hex = le_u64_hex(entry, 8)
    local pid = le_u32(entry, 16)
    local tid_low = le_u32(entry, 20)
    local ts_ns = le_u64_number(entry, 24)
    local direction = le_u16(entry, 32)
    local api = le_u16(entry, 34)
    local function_code = le_u32(entry, 36)
    if not pid or not tid_low or not direction or not api or not function_code then
        return nil, "invalid fixed header"
    end

    local rec = {
        entry_len = entry_len,
        entry_type = entry_type,
        version = version,
        seq_hex = seq_hex or "0x0",
        pid = pid,
        tid_low = tid_low,
        timestamp_ns = ts_ns,
        direction = direction,
        api = api,
        function_code = function_code,
        kind = entry_kind_name(api, direction),
        sections = {},
        backtrace = {},
        backtrace_symbols = {},
        mach = { descriptors = {} },
        xpc = { serialized = {}, strings = {} },
    }

    local sec_off = 40
    while (sec_off + 8) <= #entry do
        local sec_type = le_u16(entry, sec_off)
        local sec_flags = le_u16(entry, sec_off + 2)
        local sec_len = le_u32(entry, sec_off + 4)
        if not sec_type or not sec_flags or not sec_len then break end

        local payload_off = sec_off + 8
        if (payload_off + sec_len) > #entry then
            break
        end
        local payload = entry:sub(payload_off + 1, payload_off + sec_len)
        local sec = {
            type = sec_type,
            flags = sec_flags,
            len = sec_len,
            payload = payload,
        }
        rec.sections[#rec.sections + 1] = sec

        if sec_type == XNIFF_V2_SEC_MACH_HEADER_OPTIONS and #payload >= 128 then
            local mach = rec.mach
            mach.api = le_u32(payload, 0)
            mach.direction = le_u32(payload, 4)
            mach.option_lo = le_u32(payload, 8)
            mach.option_hi = le_u32(payload, 12)
            mach.msgh_size = le_u32(payload, 16)
            mach.copy_len = le_u32(payload, 20)
            mach.msg_addr_hex = le_u64_hex(payload, 24)
            mach.aux_addr_hex = le_u64_hex(payload, 32)
            mach.ret_hex = le_u64_hex(payload, 40)
            mach.desc_count = le_u32(payload, 48)
            mach.priority = le_u32(payload, 52)
            mach.timeout_hex = le_u64_hex(payload, 56)
            mach.option64_hex = string.format("0x%08x%08x", mach.option_hi or 0, mach.option_lo or 0)
            mach.is_send = ((mach.option_lo or 0) & MACH_SEND_MSG) ~= 0
            mach.is_recv = ((mach.option_lo or 0) & MACH_RCV_MSG) ~= 0
            mach.args = {}
            for i = 0, 7 do
                mach.args[i + 1] = le_u64_hex(payload, 64 + (i * 8)) or "0x0"
            end
        elseif sec_type == XNIFF_V2_SEC_MACH_INLINE_BYTES then
            rec.mach.inline_bytes = payload
            if #payload >= 24 then
                rec.mach.msgh_bits = le_u32(payload, 0)
                rec.mach.msgh_size_hdr = le_u32(payload, 4)
                rec.mach.remote = le_u32(payload, 8)
                rec.mach.local_port = le_u32(payload, 12)
                rec.mach.voucher = le_u32(payload, 16)
                rec.mach.msgh_id = le_i32(payload, 20)
            end
        elseif sec_type == XNIFF_V2_SEC_MACH_TRAILER_BYTES then
            rec.mach.trailer_bytes = payload
        elseif sec_type == XNIFF_V2_SEC_MACH_DESC_META and #payload >= 40 then
            local desc = {
                index = le_u32(payload, 0),
                desc_type = le_u16(payload, 4),
                desc_flags = le_u16(payload, 6),
                address_hex = le_u64_hex(payload, 8),
                size_bytes = le_u32(payload, 16),
                count = le_u32(payload, 20),
                elem_size = le_u32(payload, 24),
                port_name = le_u32(payload, 28),
                port_disposition = le_u32(payload, 32),
            }
            rec.mach.descriptors[#rec.mach.descriptors + 1] = desc
        elseif sec_type == XNIFF_V2_SEC_MACH_DESC_OOL_BYTES or sec_type == XNIFF_V2_SEC_MACH_DESC_PORT_ARRAY then
            local d = rec.mach.descriptors[#rec.mach.descriptors]
            if d then
                d.bytes = payload
                d.bytes_kind = sec_type
            end
        elseif sec_type == XNIFF_V2_SEC_XPC_CALL_META and #payload >= 104 then
            local xpc = rec.xpc
            xpc.api = le_u32(payload, 0)
            xpc.direction = le_u32(payload, 4)
            xpc.func = le_u32(payload, 8)
            xpc.conn_pid = le_u32(payload, 12)
            xpc.ret_hex = le_u64_hex(payload, 16)
            xpc.args = {}
            for i = 0, 7 do
                xpc.args[i + 1] = le_u64_hex(payload, 24 + (i * 8)) or "0x0"
            end
            xpc.str_lens = {
                le_u32(payload, 88) or 0,
                le_u32(payload, 92) or 0,
                le_u32(payload, 96) or 0,
                le_u32(payload, 100) or 0,
            }
            local so = 104
            for i = 1, 4 do
                local sl = xpc.str_lens[i] or 0
                if sl > 0 and (so + sl) <= #payload then
                    xpc.strings[i] = payload:sub(so + 1, so + sl)
                    so = so + sl
                else
                    xpc.strings[i] = ""
                end
            end
            xpc.func_name = xpc_func_name(xpc.func or rec.function_code)
            xpc.flow = xpc_flow(xpc.func or rec.function_code)
            xpc.role = xpc_role(xpc.func or rec.function_code, xpc.direction or rec.direction)
            if xpc.args and #xpc.args >= 2 then
                if (xpc.func or 0) == XNIFF_XPC_FUNC_CONNECTION_CREATE then
                    xpc.conn_ptr = xpc.ret_hex
                else
                    xpc.conn_ptr = xpc.args[1]
                end
                xpc.msg_ptr = xpc.args[2]
            end
        elseif sec_type == XNIFF_V2_SEC_XPC_SERIALIZED and #payload >= 12 then
            local slot = payload:byte(1) or 0
            local fmt = payload:byte(2) or 0
            local flags = le_u16(payload, 2) or 0
            local original_len = le_u32(payload, 4) or 0
            local stored_len = le_u32(payload, 8) or 0
            local bytes_avail = #payload - 12
            local keep = stored_len
            if keep > bytes_avail then keep = bytes_avail end
            if keep < 0 then keep = 0 end
            local bytes = payload:sub(13, 12 + keep)
            local slot_name = xpc_slot_name(slot)
            rec.xpc.serialized[slot_name] = {
                slot = slot,
                format = fmt,
                format_name = xpc_format_name(fmt),
                flags = flags,
                original_len = original_len,
                stored_len = keep,
                truncated = (flags & 1) ~= 0,
                bytes = bytes,
            }
        elseif sec_type == XNIFF_V2_SEC_XPC_CONN_META and #payload >= 128 then
            local cm = {}
            cm.version = le_u32(payload, 0) or 0
            cm.flags = le_u32(payload, 4) or 0
            cm.pid_public = le_u32(payload, 8) or 0
            cm.name_public_len = le_u32(payload, 120) or 0
            cm.name_private_len = le_u32(payload, 124) or 0
            local so = 128
            if cm.name_public_len > 0 and (so + cm.name_public_len) <= #payload then
                cm.name_public = payload:sub(so + 1, so + cm.name_public_len)
                so = so + cm.name_public_len
            end
            if cm.name_private_len > 0 and (so + cm.name_private_len) <= #payload then
                cm.name_private = payload:sub(so + 1, so + cm.name_private_len)
            end
            rec.xpc.conn_meta = cm
            if (cm.flags & XNIFF_XPC_CONN_META_HAS_PID_PUBLIC) ~= 0 and (rec.xpc.conn_pid or 0) == 0 then
                rec.xpc.conn_pid = cm.pid_public
            end
            if (cm.flags & XNIFF_XPC_CONN_META_HAS_NAME_PUBLIC) ~= 0 and cm.name_public and cm.name_public ~= "" then
                rec.xpc.conn_name = cm.name_public
            end
        elseif sec_type == XNIFF_V2_SEC_HOOK_DIAG and #payload >= 8 then
            local msg_len = le_u32(payload, 0) or 0
            if msg_len > (#payload - 8) then msg_len = #payload - 8 end
            rec.diag = payload:sub(9, 8 + msg_len)
        elseif sec_type == XNIFF_V2_SEC_BACKTRACE and #payload >= 8 then
            local count = le_u32(payload, 0) or 0
            local avail = math.floor((#payload - 8) / 8)
            if count > 32 then count = 32 end
            if count > avail then count = avail end
            local pcs = {}
            for i = 0, count - 1 do
                pcs[#pcs + 1] = le_u64_hex(payload, 8 + (i * 8)) or "0x0"
            end
            rec.backtrace = pcs
        elseif sec_type == XNIFF_V2_SEC_BACKTRACE_SYMBOLS and #payload >= 8 then
            local count = le_u32(payload, 0) or 0
            local strings_len = le_u32(payload, 4) or 0
            if count > 32 then count = 32 end
            local rec_bytes = count * 24
            local rec_off = 8
            local str_off = rec_off + rec_bytes
            local str_end = str_off + strings_len
            if str_end > #payload then str_end = #payload end
            if (rec_off + rec_bytes) <= #payload and str_off <= #payload then
                local so = str_off
                local syms = {}
                for i = 0, count - 1 do
                    local ro = rec_off + (i * 24)
                    local pc = le_u64_hex(payload, ro) or "0x0"
                    local sym_addr = le_u64_hex(payload, ro + 8) or "0x0"
                    local name_len = le_u32(payload, ro + 16) or 0
                    local image_len = le_u32(payload, ro + 20) or 0
                    if (so + name_len + image_len) > str_end then break end
                    local name = ""
                    if name_len > 0 then
                        name = payload:sub(so + 1, so + name_len)
                        so = so + name_len
                    end
                    local image = ""
                    if image_len > 0 then
                        image = payload:sub(so + 1, so + image_len)
                        so = so + image_len
                    end
                    syms[#syms + 1] = {
                        pc = pc,
                        sym_addr = sym_addr,
                        name = name,
                        image = image,
                    }
                end
                rec.backtrace_symbols = syms
            end
        elseif sec_type == XNIFF_V2_SEC_CALL_ID and #payload >= 8 then
            rec.wire_call_id = le_u64_hex(payload, 0)
        end

        sec_off = payload_off + sec_len
    end

    if not rec.xpc.func_name then
        rec.xpc.func_name = xpc_func_name(rec.function_code)
    end
    if not rec.xpc.flow then
        rec.xpc.flow = xpc_flow(rec.function_code)
    end
    if not rec.xpc.role then
        rec.xpc.role = xpc_role(rec.function_code, rec.direction)
    end

    return rec
end

local function choose_payload_for_record(rec)
    if not rec then return "", "none" end
    if rec.api == XNIFF_API_MACH_MSG or rec.api == XNIFF_API_MACH_MSG2 then
        if rec.mach and rec.mach.inline_bytes and #rec.mach.inline_bytes > 0 then
            return rec.mach.inline_bytes, "mach.inline"
        end
    elseif rec.api == XNIFF_API_XPC_HL then
        local order = nil
        if rec.function_code == XNIFF_XPC_FUNC_CONNECTION_CALL_EVENT_HANDLER then
            order = { "event", "message", "reply" }
        elseif rec.direction == XNIFF_DIR_EXIT then
            order = { "reply", "message", "event" }
        else
            order = { "message", "event", "reply" }
        end
        for _, slot_name in ipairs(order) do
            local slot = rec.xpc and rec.xpc.serialized and rec.xpc.serialized[slot_name]
            if slot and slot.bytes and #slot.bytes > 0 then
                return slot.bytes, "xpc.serialized." .. slot_name
            end
        end
    elseif rec.api == XNIFF_API_DEBUG and rec.diag and #rec.diag > 0 then
        return rec.diag, "diag.text"
    end
    return "", "none"
end

local function encap_for_record(rec)
    if not rec then return XNIFF_JSON_ENCAP end
    if rec.api == XNIFF_API_XPC_HL then return XNIFF_XPC_ENCAP end
    if rec.api == XNIFF_API_MACH_MSG or rec.api == XNIFF_API_MACH_MSG2 then return XNIFF_MACH_ENCAP end
    if rec.api == XNIFF_API_DEBUG then return XNIFF_DIAG_ENCAP end
    if rec.entry_type == 2 then return XNIFF_XPC_ENCAP end
    if rec.entry_type == 1 then return XNIFF_MACH_ENCAP end
    return XNIFF_DIAG_ENCAP
end

local function assign_call_id(st, rec)
    if not st or not rec then
        return nil
    end
    if rec.wire_call_id then
        local wire_key = tostring(rec.pid or 0) .. ":" .. rec.wire_call_id
        local wire_id = st.wire_calls[wire_key]
        if wire_id then return wire_id end
        wire_id = st.next_call_id
        st.next_call_id = st.next_call_id + 1
        st.wire_calls[wire_key] = wire_id
        return wire_id
    end

    local key = table.concat({
        tostring(rec.pid or 0),
        tostring(rec.tid_low or 0),
        tostring(rec.api or 0),
        tostring(rec.function_code or 0),
    }, ":")
    local id = nil
    if rec.direction == XNIFF_DIR_ENTRY then
        id = st.next_call_id
        st.next_call_id = st.next_call_id + 1
        local stack = st.inflight[key]
        if not stack then
            stack = {}
            st.inflight[key] = stack
        end
        stack[#stack + 1] = id
    elseif rec.direction == XNIFF_DIR_EXIT then
        local stack = st.inflight[key]
        if stack and #stack > 0 then
            id = table.remove(stack)
            if #stack == 0 then st.inflight[key] = nil end
        else
            id = st.next_call_id
            st.next_call_id = st.next_call_id + 1
        end
    else
        id = st.next_call_id
        st.next_call_id = st.next_call_id + 1
    end
    return id
end

local function apply_record_to_frame(frame, rec, st)
    local payload, payload_view = choose_payload_for_record(rec)
    rec.payload_view = payload_view
    rec.payload = payload

    frame.encap = encap_for_record(rec)
    frame.data = payload
    frame.captured_length = #payload
    frame.original_length = #payload

    if rec.timestamp_ns then
        local sec, nsec = ts_from_ns_for_frame(rec.timestamp_ns, st)
        local t = nstime_new(sec, nsec)
        if t then frame.time = t end
    end
end

local function bin_read_record_at_current(file)
    local offset = file:seek()
    local h = file:read(16)
    if not h then
        return false
    end
    if #h ~= 16 then
        return nil
    end
    local entry_len = le_u32(h, 0)
    local version = le_u16(h, 6)
    if not entry_len or not version then
        return nil
    end
    if version ~= XNIFF_IPC_V2_VERSION then
        return nil
    end
    if entry_len < 40 or entry_len > (64 * 1024 * 1024) then
        return nil
    end
    local tail = file:read(entry_len - 16)
    if not tail or #tail ~= (entry_len - 16) then
        return nil
    end
    local entry = h .. tail
    local rec, err = parse_v2_record(entry)
    if not rec then
        return nil, err
    end
    rec.offset = offset
    return rec
end

local function bin_read_frame(file, capture, frame, is_seek)
    local st = capture.private_table
    if type(st) ~= "table" then
        return false
    end

    if st.mode == "file" and not st.file_hdr_consumed then
        local fh = file:read(8)
        if not fh or #fh ~= 8 then
            return false
        end
        st.file_hdr_consumed = true
    end

    local offset = file:seek()
    local rec, err = bin_read_record_at_current(file)
    if rec == false then
        return false
    end
    if not rec then
        if err then
            return false
        end
        return false
    end

    local frame_no = nil
    if is_seek then
        frame_no = st.offset_to_frame[offset]
    else
        frame_no = st.next_frame_no
        st.next_frame_no = st.next_frame_no + 1
        st.offset_to_frame[offset] = frame_no
    end
    if not frame_no or frame_no <= 0 then
        frame_no = st.next_frame_no
        st.next_frame_no = st.next_frame_no + 1
        st.offset_to_frame[offset] = frame_no
    end

    if not is_seek then
        rec.event_id = frame_no
        rec.call_id = assign_call_id(st, rec)
        g_bin_records_by_frame[frame_no] = rec
    else
        local existing = g_bin_records_by_frame[frame_no]
        if existing then
            rec = existing
        else
            rec.event_id = frame_no
            rec.call_id = nil
            g_bin_records_by_frame[frame_no] = rec
        end
    end

    apply_record_to_frame(frame, rec, st)
    return offset
end

local fh_bin = FileHandler.new("XNIFF Binary", "xniff_bin", "XNIFF binary v2 capture reader", "rms")
fh_bin.extensions = "xniffbin;xniff.bin"

function fh_bin.read_open(file, capture)
    local pos = file:seek()
    local head = file:read(16) or ""
    file:seek("set", pos)
    if #head < 8 then
        return false
    end

    local mode = nil
    local magic = le_u32(head, 0)
    local version = le_u16(head, 4)
    if magic == XNIFF_BIN_FILE_MAGIC and version == XNIFF_BIN_FILE_VERSION then
        mode = "file"
    else
        local entry_len = le_u32(head, 0)
        local entry_ver = le_u16(head, 6)
        if entry_len and entry_ver and entry_ver == XNIFF_IPC_V2_VERSION and entry_len >= 40 and entry_len <= (64 * 1024 * 1024) then
            mode = "raw"
        end
    end

    if not mode then
        return false
    end

    capture.encap = XNIFF_DIAG_ENCAP
    if wtap_file_tsprec and wtap_file_tsprec.NSEC then
        capture.time_precision = wtap_file_tsprec.NSEC
    end
    capture.snapshot_length = 0
    capture.user_app = "xniff-bin.lua"
    capture.private_table = {
        mode = mode,
        file_hdr_consumed = false,
        next_frame_no = 1,
        offset_to_frame = {},
        inflight = {},
        wire_calls = {},
        next_call_id = 1,
        base_mono_ns = nil,
        base_epoch = nil,
    }

    g_bin_records_by_frame = {}
    return true
end

fh_bin.read = function(file, capture, frame)
    return bin_read_frame(file, capture, frame, false)
end

function fh_bin.seek_read(file, capture, frame, offset)
    local st = capture.private_table
    if type(st) ~= "table" then return false end
    if not file:seek("set", offset) then
        return false
    end
    local frame_no = st.offset_to_frame[offset]
    if frame_no and g_bin_records_by_frame[frame_no] then
        apply_record_to_frame(frame, g_bin_records_by_frame[frame_no], st)
        return true
    end
    local rc = bin_read_frame(file, capture, frame, true)
    if rc == false then return false end
    return true
end

register_filehandler(fh_bin)

local xniff_mach = Proto("xniff_mach", "XNIFF Mach")
local xniff_xpc = Proto("xniff_xpc", "XNIFF XPC")
local xniff_diag = Proto("xniff_diag", "XNIFF Debug")

local function add_common_record_fields(root, tvb, rec, func_name, flow)
    add_if_num(root, tvb, f_event_id, rec.event_id)
    add_if_num(root, tvb, f_call_id, rec.call_id)
    add_if_num(root, tvb, f_pid, rec.pid)
    add_if_num(root, tvb, f_tid_low, rec.tid_low)
    add_if_num(root, tvb, f_api, rec.api)
    add_if_num(root, tvb, f_direction, rec.direction)
    add_if_num(root, tvb, f_function, rec.function_code)
    add_if_str(root, tvb, f_seq, rec.seq_hex)
    add_if_str(root, tvb, f_kind, rec.kind)
    add_if_str(root, tvb, f_func_name, func_name)
    add_if_str(root, tvb, f_flow, flow)
    add_if_str(root, tvb, f_payload_view, rec.payload_view)
end

local function render_backtrace(root, tvb, rec)
    if rec.backtrace and #rec.backtrace > 0 then
        local bt = root:add(tvb(0, 0), "Backtrace")
        for i, pc in ipairs(rec.backtrace) do
            local sym = rec.backtrace_symbols and rec.backtrace_symbols[i] or nil
            local line = "#" .. tostring(i - 1) .. " " .. tostring(pc)
            if sym and sym.name and sym.name ~= "" then
                line = line .. " " .. sym.name
            end
            if sym and sym.image and sym.image ~= "" then
                line = line .. " (" .. sym.image .. ")"
            end
            bt:add(tvb(0, 0), line)
        end
    end
end

local function render_serialized_slot_bin(tree, tvb, slot_name, slot)
    if not slot or not slot.bytes then return end
    local st = tree:add(tvb(0, 0), "serialized." .. slot_name)
    st:add(tvb(0, 0), "format: " .. tostring(slot.format_name or slot.format or "unknown"))
    st:add(tvb(0, 0), "stored_len: " .. tostring(slot.stored_len or #slot.bytes))
    st:add(tvb(0, 0), "original_len: " .. tostring(slot.original_len or 0))
    st:add(tvb(0, 0), "truncated: " .. tostring(slot.truncated == true))
    st:add(tvb(0, 0), "wire_hex_preview: " .. bytes_to_hex(slot.bytes, 64))

    local decoded, derr = decode_xpc_serialized_bin(slot.bytes)
    if decoded then
        st:add(tvb(0, 0), "decode_mode: " .. tostring(decoded.mode))
        st:add(tvb(0, 0), "nodes: " .. tostring(decoded.nodes))
        st:add(tvb(0, 0), "consumed_bytes: " .. tostring(decoded.consumed))
        if decoded.remaining and decoded.remaining > 0 then
            st:add(tvb(0, 0), "remaining_bytes: " .. tostring(decoded.remaining))
        end
        render_xpc_obj(st, tvb, "root", decoded.root, 0)
    else
        st:add(tvb(0, 0), "xpc_decode_error: " .. tostring(derr))
        local plist, perr = decode_bplist(slot.bytes)
        if plist then
            local p_tree = st:add(tvb(0, 0), "bplist_root")
            render_bplist_meta(p_tree, tvb, plist)
            render_bplist_obj(p_tree, tvb, "root", plist.top, 0)
        else
            st:add(tvb(0, 0), "bplist_decode_error: " .. tostring(perr))
            maybe_decode_embedded_blob(st, tvb, slot.bytes, 0)
        end
    end

    local dump = make_hexdump(slot.bytes)
    if dump ~= "" then
        local hd = st:add(tvb(0, 0), "hexdump")
        hd:set_text(dump)
    end
end

function xniff_mach.dissector(tvb, pinfo, tree)
    local rec = g_bin_records_by_frame[pinfo.number]
    pinfo.cols.protocol = "MACH"
    local root = tree:add(xniff_mach, tvb(), "XNIFF Mach Event")
    if not rec then
        root:add(tvb(0, 0), "missing parsed metadata for frame")
        return
    end

    local func_name = mach_function_name(rec.function_code)
    add_common_record_fields(root, tvb, rec, func_name, nil)

    local src = tostring(rec.pid or "?")
    local dst = "?"
    if rec.mach and rec.mach.remote then
        dst = string.format("0x%08x", rec.mach.remote)
    end
    if rec.mach and rec.mach.is_recv then
        src, dst = dst, src
    end
    pinfo.cols.src = src
    pinfo.cols.dst = dst

    local info = {}
    info[#info + 1] = func_name
    if rec.event_id then info[#info + 1] = "event=" .. tostring(rec.event_id) end
    if rec.call_id then info[#info + 1] = "call=" .. tostring(rec.call_id) end
    if rec.mach and rec.mach.msgh_id then info[#info + 1] = "msgh_id=" .. tostring(rec.mach.msgh_id) end
    info[#info + 1] = "payload=" .. tostring(rec.payload_view or "none")
    pinfo.cols.info = table.concat(info, " ")

    local mach = rec.mach or {}
    local mt = root:add(tvb(0, 0), "Mach Header/Options")
    mt:add(tvb(0, 0), "option64: " .. tostring(mach.option64_hex or ""))
    mt:add(tvb(0, 0), "msgh_size: " .. tostring(mach.msgh_size or mach.msgh_size_hdr or 0))
    mt:add(tvb(0, 0), "copy_len: " .. tostring(mach.copy_len or 0))
    mt:add(tvb(0, 0), "msg_addr: " .. tostring(mach.msg_addr_hex or ""))
    mt:add(tvb(0, 0), "aux_addr: " .. tostring(mach.aux_addr_hex or ""))
    mt:add(tvb(0, 0), "ret: " .. tostring(mach.ret_hex or ""))
    mt:add(tvb(0, 0), "desc_count: " .. tostring(mach.desc_count or 0))
    mt:add(tvb(0, 0), "priority: " .. tostring(mach.priority or 0))
    mt:add(tvb(0, 0), "timeout: " .. tostring(mach.timeout_hex or ""))
    mt:add(tvb(0, 0), "is_send: " .. tostring(mach.is_send == true))
    mt:add(tvb(0, 0), "is_recv: " .. tostring(mach.is_recv == true))
    if mach.msgh_bits then mt:add(tvb(0, 0), "msgh_bits: 0x" .. string.format("%08x", mach.msgh_bits)) end
    if mach.msgh_size_hdr then mt:add(tvb(0, 0), "msgh_size_hdr: " .. tostring(mach.msgh_size_hdr)) end
    if mach.msgh_id then mt:add(tvb(0, 0), "msgh_id: " .. tostring(mach.msgh_id)) end
    if mach.remote then mt:add(tvb(0, 0), "remote: 0x" .. string.format("%08x", mach.remote)) end
    if mach.local_port then mt:add(tvb(0, 0), "local: 0x" .. string.format("%08x", mach.local_port)) end
    if mach.voucher then mt:add(tvb(0, 0), "voucher: 0x" .. string.format("%08x", mach.voucher)) end
    if mach.args and #mach.args > 0 then
        local at = mt:add(tvb(0, 0), "args")
        for i, a in ipairs(mach.args) do
            at:add(tvb(0, 0), "x" .. tostring(i - 1) .. ": " .. tostring(a))
        end
    end

    if mach.inline_bytes and #mach.inline_bytes > 0 then
        local inline_tree = root:add(tvb(0, 0), "Mach Inline Bytes (" .. tostring(#mach.inline_bytes) .. " bytes)")
        inline_tree:add(tvb(0, 0), "hex_preview: " .. bytes_to_hex(mach.inline_bytes, 64))
        maybe_decode_embedded_blob(inline_tree, tvb, mach.inline_bytes, 0)
    end
    if mach.trailer_bytes and #mach.trailer_bytes > 0 then
        local tr = root:add(tvb(0, 0), "Mach Trailer Bytes (" .. tostring(#mach.trailer_bytes) .. " bytes)")
        tr:add(tvb(0, 0), "hex_preview: " .. bytes_to_hex(mach.trailer_bytes, 64))
    end

    if mach.descriptors and #mach.descriptors > 0 then
        local dt = root:add(tvb(0, 0), "Mach Descriptors")
        for i, d in ipairs(mach.descriptors) do
            local dnode = dt:add(tvb(0, 0), "descriptor[" .. tostring(i - 1) .. "]")
            dnode:add(tvb(0, 0), "type: " .. tostring(d.desc_type or 0))
            dnode:add(tvb(0, 0), "flags: " .. tostring(d.desc_flags or 0))
            dnode:add(tvb(0, 0), "address: " .. tostring(d.address_hex or ""))
            dnode:add(tvb(0, 0), "size_bytes: " .. tostring(d.size_bytes or 0))
            dnode:add(tvb(0, 0), "count: " .. tostring(d.count or 0))
            dnode:add(tvb(0, 0), "elem_size: " .. tostring(d.elem_size or 0))
            dnode:add(tvb(0, 0), "port_name: " .. tostring(d.port_name or 0))
            dnode:add(tvb(0, 0), "port_disposition: " .. tostring(d.port_disposition or 0))
            if d.bytes and #d.bytes > 0 then
                dnode:add(tvb(0, 0), "data_hex_preview: " .. bytes_to_hex(d.bytes, 64))
                maybe_decode_embedded_blob(dnode, tvb, d.bytes, 1)
            end
        end
    end

    render_backtrace(root, tvb, rec)
end

function xniff_xpc.dissector(tvb, pinfo, tree)
    local rec = g_bin_records_by_frame[pinfo.number]
    pinfo.cols.protocol = "XPC"
    local root = tree:add(xniff_xpc, tvb(), "XNIFF XPC Event")
    if not rec then
        root:add(tvb(0, 0), "missing parsed metadata for frame")
        return
    end

    local xpc = rec.xpc or {}
    local func_name = xpc.func_name or xpc_func_name(rec.function_code)
    local flow = xpc.flow or xpc_flow(rec.function_code)
    local role = xpc.role or xpc_role(rec.function_code, rec.direction)
    add_common_record_fields(root, tvb, rec, func_name, flow)
    add_if_str(root, tvb, f_role, role)

    local conn_pid = xpc.conn_pid or 0
    local src = tostring(rec.pid or "?")
    local dst = (conn_pid ~= 0) and tostring(conn_pid) or "?"
    if flow == "recv" then
        src, dst = dst, src
    end
    pinfo.cols.src = src
    pinfo.cols.dst = dst

    local info = {}
    info[#info + 1] = func_name
    if rec.event_id then info[#info + 1] = "event=" .. tostring(rec.event_id) end
    if rec.call_id then info[#info + 1] = "call=" .. tostring(rec.call_id) end
    info[#info + 1] = "role=" .. tostring(role)
    info[#info + 1] = "flow=" .. tostring(flow)
    info[#info + 1] = "payload=" .. tostring(rec.payload_view or "none")
    pinfo.cols.info = table.concat(info, " ")

    add_if_num(root, tvb, f_conn_pid, conn_pid)
    add_if_str(root, tvb, f_conn_name, xpc.conn_name)
    add_if_str(root, tvb, f_conn_ptr, xpc.conn_ptr)
    add_if_str(root, tvb, f_msg_ptr, xpc.msg_ptr)

    local call_tree = root:add(tvb(0, 0), "XPC Call Metadata")
    call_tree:add(tvb(0, 0), "func: " .. tostring(func_name))
    call_tree:add(tvb(0, 0), "role: " .. tostring(role))
    if rec.wire_call_id then
        call_tree:add(tvb(0, 0), "wire_call_id: " .. tostring(rec.wire_call_id))
    end
    call_tree:add(tvb(0, 0), "ret: " .. tostring(xpc.ret_hex or ""))
    if xpc.args and #xpc.args > 0 then
        local arg_tree = call_tree:add(tvb(0, 0), "args")
        for i, arg in ipairs(xpc.args) do
            local arg_name = xpc_arg_name(rec.function_code, i - 1)
            if arg_name then
                arg_tree:add(tvb(0, 0), "arg." .. arg_name .. ": " .. tostring(arg))
            else
                arg_tree:add(tvb(0, 0), "arg[" .. tostring(i - 1) .. "]: " .. tostring(arg))
            end
        end
    end

    local names = xpc_string_field_names(rec.kind or "", rec.function_code)
    for i = 1, 4 do
        local s = xpc.strings and xpc.strings[i] or nil
        if s and s ~= "" then
            local label = names[i] or ("slot_" .. tostring(i - 1))
            call_tree:add(tvb(0, 0), label .. ": " .. safe_ascii(s, 512))
            if label == "target_service_name" or label == "connection_name" then
                add_if_str(root, tvb, f_service_name, s)
            end
        end
    end

    if xpc.conn_meta then
        local cm = xpc.conn_meta
        local cmt = root:add(tvb(0, 0), "XPC Connection Metadata")
        cmt:add(tvb(0, 0), "version: " .. tostring(cm.version or 0))
        cmt:add(tvb(0, 0), "flags: 0x" .. string.format("%x", cm.flags or 0))
        cmt:add(tvb(0, 0), "pid_public: " .. tostring(cm.pid_public or 0))
        if cm.name_public and cm.name_public ~= "" then
            cmt:add(tvb(0, 0), "name_public: " .. safe_ascii(cm.name_public, 512))
        end
        if cm.name_private and cm.name_private ~= "" then
            cmt:add(tvb(0, 0), "name_private: " .. safe_ascii(cm.name_private, 512))
        end
    end

    local has_message = xpc.serialized and xpc.serialized.message ~= nil
    local has_reply = xpc.serialized and xpc.serialized.reply ~= nil
    local has_event = xpc.serialized and xpc.serialized.event ~= nil
    add_if_bool(root, tvb, f_has_serialized_message, has_message)
    add_if_bool(root, tvb, f_has_serialized_reply, has_reply)
    add_if_bool(root, tvb, f_has_serialized_event, has_event)
    add_if_num(root, tvb, f_serialized_message_len, has_message and xpc.serialized.message.stored_len or nil)
    add_if_num(root, tvb, f_serialized_reply_len, has_reply and xpc.serialized.reply.stored_len or nil)
    add_if_num(root, tvb, f_serialized_event_len, has_event and xpc.serialized.event.stored_len or nil)

    if has_message or has_reply or has_event then
        local ser_tree = root:add(tvb(0, 0), "XPC Serialized Decode (xpcdesert-like)")
        if has_message then render_serialized_slot_bin(ser_tree, tvb, "message", xpc.serialized.message) end
        if has_reply then render_serialized_slot_bin(ser_tree, tvb, "reply", xpc.serialized.reply) end
        if has_event then render_serialized_slot_bin(ser_tree, tvb, "event", xpc.serialized.event) end
    end

    render_backtrace(root, tvb, rec)
end

function xniff_diag.dissector(tvb, pinfo, tree)
    local rec = g_bin_records_by_frame[pinfo.number]
    pinfo.cols.protocol = "XNIFF-DBG"
    local root = tree:add(xniff_diag, tvb(), "XNIFF Debug Event")
    if not rec then
        root:add(tvb(0, 0), "missing parsed metadata for frame")
        return
    end
    add_common_record_fields(root, tvb, rec, "debug_log", nil)
    local msg = rec.diag or ""
    root:add(tvb(0, 0), "message: " .. safe_ascii(msg, 4096))
    pinfo.cols.src = tostring(rec.pid or "?")
    pinfo.cols.dst = "-"
    pinfo.cols.info = "debug_log payload=" .. tostring(rec.payload_view or "none")
end

if wtap_encap then
    wtap_encap:add(XNIFF_MACH_ENCAP, xniff_mach)
    wtap_encap:add(XNIFF_XPC_ENCAP, xniff_xpc)
    wtap_encap:add(XNIFF_DIAG_ENCAP, xniff_diag)
end
