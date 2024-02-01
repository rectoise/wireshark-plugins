set_plugin_info({
    version = "1.0.0",
    author = "uedaeita",
    repository = "https://github.com/rectoise/wireshark-plugins",
    description = "Wireshark plugin for DTN BP over LTP over Ethernet Protocol"
})

-- 最小 Ethernet フレーム長
local min_eth_buffer_len = 64
-- Ethernet フレームのヘッダ長
local eth_header_buffer_len = 14
-- 最小 Ethernet フレームのデータ長
local min_eth_data_buffer_len = min_eth_buffer_len - eth_header_buffer_len

--- Tvb (Testy Virtual Buffer) のフォーマット
local function formatTvb(buffer)
    local buffer_len = buffer:len()

    if min_eth_data_buffer_len < buffer_len then
        return buffer
    end

    -- Ethernet の最小フレームサイズに満たないデータ長の場合は0埋めしており、Wireshark LTP dissectorが Malformed を返す場合があるため、0埋めされている部分を除去したデータ長のバッファを返す
    for i = buffer_len, 0, -1 do
        if buffer(i, 1):uint() ~= 0 then
            return buffer(0, i):tvb()
        end
    end
    return buffer
end

--- BP over LTP over Ethernet のプロトコル定義
local BPoLTPoEProto = Proto("BPoLTPoE", "BP over LTP over Ethernet")

--- BP over LTP over Ethernet のディセクター
function BPoLTPoEProto.dissector(buffer, pinfo, tree)
    local ltp_dissector = Dissector.get("ltp")
    ltp_dissector:call(formatTvb(buffer), pinfo, tree)
end

--- プラグインの有効化
local function enablePlugin()
    local ether_table = DissectorTable.get("ethertype")
    for i = 65280, 65536 do -- ff00 ~ ffff
        ether_table:add(i, BPoLTPoEProto)
    end
end

enablePlugin()
