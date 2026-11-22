-- TCP stream statistics for Wireshark and TShark.
local stream = Field.new("tcp.stream")
local length = Field.new("tcp.len")
local flags = Field.new("tcp.flags")

local function observe(render)
    local tap = Listener.new("frame", "tcp")
    local streams = {}
    function tap.reset() streams = {} end
    function tap.packet(pinfo)
        local sid, size, bits = stream(), length(), flags()
        if not (sid and size and bits) then return end
        local id = tonumber(sid.value)
        local host = tostring(pinfo.src)
        local port = tonumber(pinfo.src_port)
        local row = streams[id]
        if not row then
            row = {host=host, port=port, remote=tostring(pinfo.dst), peer=tonumber(pinfo.dst_port),
                   packets={0,0}, bytes={0,0}, syn=0, fin=0, rst=0}
            streams[id] = row
        end
        local dir = (row.host == host and row.port == port) and 1 or 2
        row.packets[dir] = row.packets[dir] + 1
        row.bytes[dir] = row.bytes[dir] + tonumber(size.value)
        local f = tonumber(bits.value)
        -- Include SYN+ACK in SYN counts; count observed segments, including retries.
        row.syn = row.syn + math.floor(f / 2) % 2
        row.fin = row.fin + f % 2
        row.rst = row.rst + math.floor(f / 4) % 2
    end
    function tap.draw()
        local ids = {}
        for id in pairs(streams) do ids[#ids+1] = id end
        table.sort(ids)
        local lines = {"stream\tA\tportA\tB\tportB\tA_pkts\tB_pkts\tA_bytes\tB_bytes\tSYN\tFIN\tRST"}
        for _, id in ipairs(ids) do
            local r = streams[id]
            lines[#lines+1] = table.concat({id,r.host,r.port,r.remote,r.peer,r.packets[1],r.packets[2],
                r.bytes[1],r.bytes[2],r.syn,r.fin,r.rst}, "\t")
        end
        render(table.concat(lines, "\n"))
    end
    return tap
end

local function show_summary()
    if not gui_enabled() then
        observe(print)
        return
    end
    local window = TextWindow.new("Lab 1A TCP stream summary")
    local tap = observe(function(text) window:set(text) end)
    window:set_atclose(function() tap:remove() end)
    retap_packets()
end

if gui_enabled() then
    register_menu("Lab 1A/TCP stream summary", show_summary, MENU_TOOLS_UNSORTED)
end
register_stat_cmd_arg("lab1,flows", show_summary)
