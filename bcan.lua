bcan_proto = Proto("bcan", "bxCAN")

local bit = require("bit");
local band, rshift, tobit, tohex = bit.band, bit.rshift, bit.tobit, bit.tohex

local f = bcan_proto.fields

-- header
f.mobid = ProtoField.uint32("bcan.mobid", "Message Object Identifier", base.HEX)
f.mobid_ide = ProtoField.bool("bcan.mobid_ide", "IDE", 32, nil, 0x80000000)
f.mobid_rtr = ProtoField.bool("bcan.mobid_rtr", "RTR", 32, nil, 0x40000000)
f.mobid_err = ProtoField.bool("bcan.mobid_err", "ERR", 32, nil, 0x20000000)
f.mobid_full = ProtoField.uint32("bcan.mobid_full", "MOB-ID", base.HEX, nil, 0x1FFFFFFF)
f.mobid_std = ProtoField.uint32("bcan.mobid_std", "STD-ID", base.HEX, nil, 0x1FFC0000)
f.mobid_ext = ProtoField.uint32("bcan.mobid_ext", "EXT-ID", base.HEX, nil, 0x0003FFFF)


function bcan_proto.dissector(buffer, pinfo, tree)
	local offset = 0
	
	local mobid = buffer(offset, 4)
	
	local ide = band(mobid:uint(), tobit(0x80000000)) == tobit(0x80000000)
	local rtr = band(mobid:uint(), tobit(0x40000000)) == tobit(0x40000000)
	local err = band(mobid:uint(), tobit(0x20000000)) == tobit(0x20000000)
	local std = rshift(band(mobid:uint(), tobit(0x1FFC0000)), 18)
	local ext = rshift(band(mobid:uint(), tobit(0x0003FFFF)), 0)
	
	local canid = ""
	
	if ide then
		canid = tohex(std,3).."."..tohex(ext,5)
	else
		canid = tohex(std,3)
	end
	
	t = tree:add(bcan_proto, "CAN: ID "..canid, buffer(offset))
	pinfo.cols['info'] = "CAN: ID ".. canid
	
	if not err then
		q = t:add(f.mobid, canid, mobid)
		q:add(f.mobid_ide, mobid)
		q:add(f.mobid_rtr, mobid)
		q:add(f.mobid_err, mobid)
		q:add(f.mobid_full, mobid)
		q:add(f.mobid_std, mobid)
		if ide then
			q:add(f.mobid_ext, mobid)
		end
	end
	
	if std == 0x80 then
		t = tree:add("CanOpen: SYNC");
		pinfo.cols['info'] = "CanOpen: SYNC"
	elseif std == 0x00 then
		t = tree:add("CanOpen: NMT");
		pinfo.cols['info'] = "CanOpen: NMT"
	end

	pinfo.cols['protocol'] = pinfo.curr_proto
	
end

register_postdissector(bcan_proto)
