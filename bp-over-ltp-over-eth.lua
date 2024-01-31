-- Wireshark dissector for BP over LTP over Ethernet

set_plugin_info({
    version = "1.0.0",
    author = "uedaeita",
    repository = "https://github.com/rectoise/wireshark-plugins"
})

-- プロトコルの定義
local bp_over_ltp_over_eth_protocol = Proto("BPoLTPoE", "BP over LTP over Ethernet")
-- Ethernet フレームのヘッダ長
local eth_header_buffer_len = 14
-- LTP の最小セグメントサイズ
local min_ltp_buffer_len = 64 - eth_header_buffer_len

-- プラグインの有効化
local function enablePlugin()
    local ether_table = DissectorTable.get("ethertype")
    for i = 65280, 65536 do -- ff00 ~ ffff
        ether_table:add(i, bp_over_ltp_over_eth_protocol)
    end
end

-- Ethernet の最小フレームサイズに満たないデータ長の場合は0埋めしており、Wireshark LTP dissectorが Malformed を返す場合があるため、0埋めされている部分を除去したデータ長のバッファを返す
local function getPreciseBuffer(buffer)
    local buffer_len = buffer:len()
    if min_ltp_buffer_len < buffer_len then
        return buffer
    end

    for i = buffer_len - 1, 0, -1 do
        if buffer(i, 1):uint() ~= 0 then
            return buffer(0, i + 1):tvb()
        end
    end

    return buffer
end

-- BPoLTPoE dissector
function bp_over_ltp_over_eth_protocol.dissector(buffer, pinfo, tree)
    local ltp_dissector = Dissector.get("ltp")
    ltp_dissector:call(getPreciseBuffer(buffer), pinfo, tree)
end

enablePlugin()
