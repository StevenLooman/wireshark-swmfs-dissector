-- swmfscol.lua
local swmfs = Proto("swmfs", "Smallworld Master Filesystem")
local swmfs_port = 1590

-- Define packet types
local request_types = {
    [0x00000000] = "INIT",
    [0x00000001] = "READ",
    [0x00000002] = "WRITE",
    [0x00000003] = "EXTEND",
    [0x00000004] = "GET LOCK",
    -- [0x00000005] = "SHUTDOWN",
    [0x00000006] = "RELEASE LOCK",
    [0x00000007] = "FLUSH",
    [0x00000008] = "REFRESH",
    [0x00000009] = "DELETE",
    [0x0000000A] = "SIZE",
    [0x0000000B] = "DECLARE USAGE",
    [0x0000000C] = "CANCEL_USAGE",
    [0x0000000D] = "GET USAGE",
    [0x0000000E] = "OPEN",
    [0x0000000F] = "CLOSE",

    [0x00000012] = "KEEPALIVE",
    [0x00000016] = "DEVICE",
    [0x00000019] = "SET NAME",
    [0x0000001B] = "HOLDER OF LOCK",
    [0x0000001C] = "SERVER_INFO",
    [0x0000001D] = "FILE IDS",
    [0x0000001E] = "FILE ID TO NAME",

    [0x00000020] = "LOCK VALUES",
    [0x00000027] = "SERVER PARAMS",

    [0x00000033] = "COMPRESSION",
    [0x00000038] = "GET RIGHTS",
    -- [0x0000003D] = "ALLOC",
}

local response_statuses = {
    [0x00000000] = "OK",
    [0x00000001] = "NEW FILE",
    [0x00000008] = "NO ACCESS",

    [0x00000020] = "NO LOCK",
}

-- Define the fields for each packet type
local fields = swmfs.fields
fields.checksum = ProtoField.uint32("swmfs.checksum", "Checksum", base.HEX)
fields.request_type = ProtoField.uint32("swmfs.request_type", "Request type", base.HEX, request_types)
fields.response_status = ProtoField.uint32("swmfs.reponse_status", "Response status", base.HEX, response_statuses)
fields.length = ProtoField.uint32("swmfs.length", "Length", base.DEC)
fields.request_id1 = ProtoField.uint32("swmfs.request_id1", "Request id1", base.DEC)
fields.request_id2 = ProtoField.uint32("swmfs.request_id2", "Request id2", base.DEC)
fields.request_arg1 = ProtoField.int32("swmfs.request_arg1", "Request arg1", base.DEC)
fields.request_arg2 = ProtoField.int32("swmfs.request_arg2", "Request arg2", base.DEC)
fields.request_arg3 = ProtoField.int32("swmfs.request_arg3", "Request arg3", base.DEC)
fields.request_data = ProtoField.uint32("swmfs.request_data", "Request data", base.DEC)
fields.request_data_str = ProtoField.stringz("swmfs.request_data_str", "data (string)")

fields.response_data = ProtoField.uint32("swmfs.response_data", "Response data", base.DEC)
fields.response_data_str = ProtoField.stringz("swmfs.response_data_str", "Response data (string)")

fields.request_init_parameters = ProtoField.stringz("swmfs.request_init_parameters", "Parameters")
fields.request_init_parameter = ProtoField.stringz("swmfs.request_init_parameter", "Parameter")


-- Helper functions
---Extract null terminated strings.
---@param buffer TvbRange
---@return integer[]
local function extract_offsets_null_terminated_strings(buffer)
    local offsets = {}
    local offset = 0
    local index = 0
    while offset < buffer:len() do
        local str_len = buffer:len() - offset
        local str = buffer(offset, str_len):stringz()

        offsets[index] = offset
        index = index + 1

        offset = offset + #str + 1
    end

    return offsets
end



-- Create the dissector function
---@param buffer Tvb
---@param pinfo Pinfo
---@param tree TreeItem
function swmfs.dissector(buffer, pinfo, tree)
    print(pinfo.cols)
    pinfo.cols.protocol = swmfs.name
    local is_from_client = pinfo.dst_port == swmfs_port
    local request_response = buffer(4, 4):le_uint()

    local swmfs_tree = tree:add(swmfs, buffer(), "Swmfs")
    swmfs_tree:add_le(fields.checksum, buffer(0, 4))
    if is_from_client then
        swmfs_tree:add_le(fields.request_type, buffer(4, 4))
    else
        swmfs_tree:add_le(fields.response_status, buffer(4, 4))
    end
    swmfs_tree:add_le(fields.length, buffer(8, 4))
    if is_from_client then
        swmfs_tree:add_le(fields.request_id1, buffer(12, 4))
        swmfs_tree:add_le(fields.request_id2, buffer(16, 4))
        swmfs_tree:add_le(fields.request_arg1, buffer(20, 4))
        swmfs_tree:add_le(fields.request_arg2, buffer(24, 4))
        swmfs_tree:add_le(fields.request_arg3, buffer(28, 4))
        if buffer:len() > 32 then
            swmfs_tree:add(fields.request_data_str, buffer(32, buffer:len() - 32))
        end
    else
        swmfs_tree:add_le(fields.response_data, buffer(12, 4))

        if buffer:len() > 16 then
            swmfs_tree:add(fields.response_data_str, buffer(16, buffer:len() - 16))
        end
    end

    -- Set info column.
    if is_from_client then
        pinfo.cols.info = string.format("%d → %d [%s] ...", pinfo.src_port, pinfo.dst_port, request_types[request_response])
        if request_types[request_response] == "INIT" then
            local strings_buffer = buffer(32)
		    local params_tree = swmfs_tree:add(swmfs, strings_buffer, "Parameters")
            local offsets = extract_offsets_null_terminated_strings(strings_buffer)
            for i = 0, #offsets do
                local offset = offsets[i]
                params_tree:add(fields.request_init_parameter, buffer(offset + 32))
            end
        end
    else -- is_from_server
        pinfo.cols.info = string.format("%d → %d [%s] ...", pinfo.src_port, pinfo.dst_port, response_statuses[request_response])

        local strings_buffer = buffer(16)
        local params_tree = swmfs_tree:add(swmfs, strings_buffer, "Parameters")
        local offsets = extract_offsets_null_terminated_strings(strings_buffer)
        for i = 0, #offsets do
            local offset = offsets[i]
            if offset ~= nil then
                params_tree:add(fields.request_init_parameter, buffer(offset + 16))
            end
        end
    end

    return true
end

local tcp_port = DissectorTable.get("tcp.port")
tcp_port:add(1590, swmfs)
