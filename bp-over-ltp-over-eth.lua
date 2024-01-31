-- Wireshark dissector for BP over LTP over Ethernet

set_plugin_info({
    version = "1.0.0",
    author = "uedaeita",
    repository = "https://github.com/rectoise/wireshark-plugins"
})

local bp_over_ltp_over_eth_protocol = Proto("BPoLTPoE", "BP over LTP over Ethernet")

function bp_over_ltp_over_eth_protocol.dissector(buffer, pinfo, tree)
    local ltp_dissector = Dissector.get("ltp")
    ltp_dissector:call(buffer, pinfo, tree)
end

local function enablePlugin()
    local ether_table = DissectorTable.get("ethertype")
    for i = 65280, 65536, 1 do -- ethertype ff00 ~ ffff
        ether_table:add(i, bp_over_ltp_over_eth_protocol)
    end
end

enablePlugin()
