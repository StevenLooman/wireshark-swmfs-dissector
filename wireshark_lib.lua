---@meta

---base.
---@enum base
base = {
    NONE = 0,
    DEC = 1,
    HEX = 2,
    OCT = 3,
    DEC_HEX = 4,
    HEX_DEC = 5,
    UNIT_STRING = 6,
    RANGE_STRING = 7,

    DOT = 11,
    DASH = 12,
    COLON = 13,
    SPACE = 14,

    LOCAL = 21,
    UTC = 22,
    DOY_UTC = 23,
}

---Encodings.
---@enum encoding
encoding = {
    ENC_ASCII = 0
}



---A table of subdissectors of a particular protocol (e.g. TCP subdissectors like http, smtp, sip are added to table "tcp.port").
---Useful to add more dissectors to a table so that they appear in the Decode As…​" dialog.
---@class DissectorTable
DissectorTable = {}

---Obtains a dissector reference by name.
---@param tablename string The short name of the table.
---@return DissectorTable
function DissectorTable.get(tablename) end

---Add a Proto with a dissector function or a Dissector object to the dissector table.
---@param pattern integer|[integer,integer]|string The pattern to match (either an integer, a integer range or a string depending on the table’s type).
---@param dissector Proto|Dissector The dissector to add (either a Proto or a Dissector).
function DissectorTable:add(pattern, dissector) end



---A refererence to a dissector, used to call a dissector against a packet or a part of it.
---@class Dissector
Dissector = {}

---Gets a Dissector object by its name.
---@param name string The name of the dissector
---@return Dissector|nil
function Dissector.get(name) end

---Gets a Lua array table of all registered Dissector names.
---Note: This is an expensive operation, and should only be used for troubleshooting.
---@return Dissector[]
function Dissector.list() end

---Calls a dissector against a given packet (or part of it).
---@param self Dissector
---@param tvb Tvb The Tvb object to dissect
---@param pinfo Pinfo The Pinfo object for packet information
---@param tree TreeItem The Tree object for protocol tree
---@return integer bytes_dissected Number of bytes dissected. Note that some dissectors always return number of bytes in incoming buffer, so be aware.
function Dissector:call(tvb, pinfo, tree) end

---Calls a dissector against a given packet (or part of it).
---@param self Dissector
---@param tvb Tvb The Tvb object to dissect
---@param pinfo Pinfo The Pinfo object for packet information
---@param tree TreeItem The Tree object for protocol tree
function Dissector:__call(tvb, pinfo, tree) end

---Gets the Dissector’s description
---@return string description A string of the Dissector’s description.
function Dissector:__tostring() end



---A new protocol in Wireshark. Protocols have several uses. The main one is to dissect a protocol, but they can also be dummies used to register preferences for other purposes.
---@class Proto
---@field fields ProtoField[] The Lua table of this dissector’s ProtoFields. ProtoFields added to this table are registered to the Proto (and any removed are deregistered if previously registered.)
Proto = {}

---Creates a new Proto object.
---@param name string The name of the protocol.
---@param description string A Long Text description of the protocol (usually lowercase).
---@return Proto proto The newly created Proto object.
function Proto.new(name, description) end

---Creates a Proto object.
---@param name string The name of the protocol.
---@param description string A Long Text description of the protocol (usually lowercase).
---@return Proto
function Proto:__call(name, description) end



---A Protocol field (to be used when adding items to the dissection tree). It must be registered via being added to a Proto.fields table.
---@class ProtoField
ProtoField = {}

---Creates a ProtoField of an unsigned 32-bit integer.
---@param abbr string Abbreviated name of the field (the string used in filters).
---@param name? string Actual name of the field (the string that appears in the tree).
---@param base? base One of base.DEC, base.HEX, base.OCT, base.DEC_HEX, base.HEX_DEC, base.UNIT_STRING, or base.RANGE_STRING.
---@param valuestring? {[string]:string} A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is base.RANGE_STRING, or a table containing the unit name for the values if base is base.UNIT_STRING.
---@param mask? integer|string Integer, String or UInt64 mask of this field.
---@param description? string Description of the field.
---@return ProtoField protoField A ProtoField object to be added to a table set to the Proto.fields attribute.
function ProtoField.uint32(abbr, name, base, valuestring, mask, description) end

---Creates a ProtoField of a signed 32-bit integer.
---@param abbr string Abbreviated name of the field (the string used in filters).
---@param name? string Actual name of the field (the string that appears in the tree).
---@param base? base One of base.DEC, base.UNIT_STRING, or base.RANGE_STRING.
---@param valuestring? {[string]:string} A table containing the text that corresponds to the values, or a table containing tables of range string values that correspond to the values ({min, max, "string"}) if the base is base.RANGE_STRING, or a table containing the unit name for the values if base is base.UNIT_STRING.
---@param mask? integer|string Integer, String or UInt64 mask of this field.
---@param description? string Description of the field.
---@return ProtoField protoField A ProtoField object to be added to a table set to the Proto.fields attribute.
function ProtoField.int32(abbr, name, base, valuestring, mask, description) end

---Creates a ProtoField of a zero-terminated string value.
---@param abbr string Abbreviated name of the field (the string used in filters).
---@param name? string Actual name of the field (the string that appears in the tree).
---@param display? base One of base.ASCII or base.UNICODE.
---@param description? string Description of the field.
---@return ProtoField protoField A ProtoField object to be added to a table set to the Proto.fields attribute.
function ProtoField.stringz(abbr, name, display, description) end



---A Tvb represents the packet’s buffer. It is passed as an argument to listeners and dissectors, and can be used to extract information (via TvbRange) from the packet’s data.
---To create a TvbRange the Tvb must be called with offset and length as optional arguments; the offset defaults to 0 and the length to tvb:captured_len().
---@class Tvb
---@operator call():TvbRange
Tvb = {}

---Equivalent to tvb:range(...)
---@param offset? integer The offset (in octets) from the beginning of the Tvb. Defaults to 0.
---@param length? integer The length (in octets) of the range. Defaults to -1, which specifies the remaining bytes in the Tvb.
---@return TvbRange
function Tvb:__call(offset, length) end

---Creates a TvbRange from this Tvb.
---@param offset? integer The offset (in octets) from the beginning of the Tvb. Defaults to 0.
---@param length? integer The length (in octets) of the range. Defaults to -1, which specifies the remaining bytes in the Tvb.
---@return TvbRange
function Tvb:range(offset, length) end

---Obtain the captured length (amount saved in the capture process) of a Tvb. Same as captured_len; kept only for backwards compatibility
---@return integer length The captured length of the Tvb.
function Tvb:len() end



---A TvbRange represents a usable range of a Tvb and is used to extract data from the Tvb that generated it.
---TvbRanges are created by calling a Tvb (e.g. 'tvb(offset,length)'). A length of -1, which is the default, means to use the bytes up to the end of the Tvb. If the TvbRange span is outside the Tvb's range the creation will cause a runtime error.
---@class TvbRange
TvbRange = {}

---Get a Little Endian unsigned integer from a TvbRange. The range must be 1-4 octets long.
---@return integer int The unsigned integer value
function TvbRange:le_uint() end

---Obtain the length of a TvbRange.
---@return integer length The length of the TvbRange.
function TvbRange:len() end

---Obtain a zero terminated string from a TvbRange.
---@param encoding? encoding The encoding to use. Defaults to ENC_ASCII.
---@return string str The string containing all bytes in the TvbRange up to the first terminating zero.
function TvbRange:stringz(encoding) end



---A Column in the packet list.
---@class Column
Column = {}



---The Columns of the packet list.
---@class Columns
Columns = {}

---Sets the text of a specific column. Some columns cannot be modified, and no error is raised if attempted. The columns that are known to allow modification are "info" and "protocol".
---@param column string The name of the column to set. Valid values are:
---Name	                Description
---====                 ===========
---number               Frame number
---abs_time             Absolute timestamp
---utc_time             UTC timestamp
---cls_time             CLS timestamp
---rel_time             Relative timestamp
---date                 Absolute date and time
---date_doy             Absolute year, day of year, and time
---utc_date             UTC date and time
---utc_date_doy         UTC year, day of year, and time
---delta_time           Delta time from previous packet
---delta_time_displayed Delta time from previous displayed packet
---src                  Source address
---src_res              Resolved source address
---src_unres            Numeric source address
---dl_src               Source data link address
---dl_src_res           Resolved source data link address
---dl_src_unres         Numeric source data link address
---net_src              Source network address
---net_src_res          Resolved source network address
---net_src_unres        Numeric source network address
---dst                  Destination address
---dst_res              Resolve destination address
---dst_unres            Numeric destination address
---dl_dst               Destination data link address
---dl_dst_res           Resolved destination data link address
---dl_dst_unres         Numeric destination data link address
---net_dst              Destination network address
---net_dst_res          Resolved destination network address
---net_dst_unres        Numeric destination network address
---src_port             Source port
---src_port_res         Resolved source port
---src_port_unres       Numeric source port
---dst_port             Destination port
---dst_port_res         Resolved destination port
---dst_port_unres       Numeric destination port
---protocol             Protocol name
---info                 General packet information
---packet_len           Packet length
---cumulative_bytes     Cumulative bytes in the capture
---direction            Packet direction
---vsan                 Virtual SAN
---tx_rate              Transmit rate
---rssi                 RSSI value
---dce_call             DCE call
---@param text string The text for the column.
function Columns:__newindex(column, text) end



---Packet information.
---@class Pinfo
---@field cols Columns Access to the packet list columns (equivalent to pinfo.columns).
---@field src_port integer Source port
---@field dst_port integer Destination port
Pinfo = {}



---TreeItems represent information in the packet details pane of Wireshark, and the packet details view of TShark. A TreeItem represents a node in the tree, which might also be a subtree and have a list of children. The children of a subtree have zero or more siblings which are other children of the same TreeItem subtree.
---During dissection, heuristic-dissection, and post-dissection, a root TreeItem is passed to dissectors as the third argument of the function callback (e.g., myproto.dissector(tvbuf,pktinfo,root)).
---In some cases the tree is not truly added to, in order to improve performance. For example for packets not currently displayed/selected in Wireshark’s visible window pane, or if TShark isn’t invoked with the -V switch. However the "add" type TreeItem functions can still be called, and still return TreeItem objects - but the info isn’t really added to the tree. Therefore you do not typically need to worry about whether there’s a real tree or not. If, for some reason, you need to know it, you can use the TreeItem.visible attribute getter to retrieve the state.
---@class TreeItem
TreeItem = {}

---Adds a child item to this tree item, returning the new child TreeItem.
---If the ProtoField represents a numeric value (int, uint or float), then it’s treated as a Big Endian (network order) value.
---This function has a complicated form: 'treeitem:add([protofield,] [tvbrange,] value], label)', such that if the first argument is a ProtoField or a Proto, the second argument is a TvbRange, and a third argument is given, it’s a value; but if the second argument is a non-TvbRange, then it’s the value (as opposed to filling that argument with 'nil', which is invalid for this function). If the first argument is a non-ProtoField and a non-Proto then this argument can be either a TvbRange or a label, and the value is not in use.
---@param protofield? ProtoField The ProtoField field or Proto protocol object to add to the tree.
---@param tvbrange? TvbRange The TvbRange of bytes in the packet this tree item covers/represents.
---@param value? any The field’s value, instead of the ProtoField/Proto one.
---@param label? string|string[] One or more strings to use for the tree item label, instead of the ProtoField/Proto one.
---@return TreeItem tree_item The new child TreeItem.
function TreeItem:add(protofield, tvbrange, value, label) end

---Adds a child item to this tree item, returning the new child TreeItem.
---If the ProtoField represents a numeric value (int, uint or float), then it’s treated as a Little Endian value.
---This function has a complicated form: 'treeitem:add_le([protofield,] [tvbrange,] value], label)', such that if the first argument is a ProtoField or a Proto, the second argument is a TvbRange, and a third argument is given, it’s a value; but if the second argument is a non-TvbRange, then it’s the value (as opposed to filling that argument with 'nil', which is invalid for this function). If the first argument is a non-ProtoField and a non-Proto then this argument can be either a TvbRange or a label, and the value is not in use.
---@param protofield? ProtoField The ProtoField field or Proto protocol object to add to the tree.
---@param tvbrange? TvbRange The TvbRange of bytes in the packet this tree item covers/represents.
---@param value? any The field’s value, instead of the ProtoField/Proto one.
---@param label? string|string[] One or more strings to use for the tree item label, instead of the ProtoField/Proto one.
---@return TreeItem tree_item The new child TreeItem.
function TreeItem:add_le(protofield, tvbrange, value, label) end

---Sets the text of the label.
---This used to return nothing, but as of 1.11.3 it returns the same tree item to allow chained calls.
---@param text string The text to be used.
---@return self
function TreeItem:set_text(text) end
