xsens_proto = Proto("xsens", "Xsens MTi Protocol")

local f = xsens_proto.fields

-- header
f.preamble = ProtoField.uint8("xsens.preamble", "Preamble", base.HEX)
f.bid = ProtoField.uint8("xsens.bid", "Bus ID", base.HEX)
f.mid = ProtoField.uint8("xsens.mid", "Message ID", base.HEX)
f.len = ProtoField.uint8("xsens.len", "Length", base.DEC)
f.extlen = ProtoField.uint16("xsens.extlen", "Ext Length", base.DEC)
f.data = ProtoField.bytes("xsens.data", "Data")
f.crc = ProtoField.uint8("xsens.crc", "Checksum", base.HEX)

function parsesingle(buffer,offset,pinfo, tree,t)
	local len = buffer(offset + 3, 1)
	local mid = buffer(offset + 2, 1)
	local length;
	
	if (len:uint() == 0xFF) then
		length = 7 + buffer(offset + 4, 2):uint();
	else
		length = 5 + len:uint(); 
	end

	local hdr = t:add(buffer(offset, length), string.format("PACKET MID=0x%02x LEN=%d",mid:uint(),length))
	hdr:add(f.mid, mid)
	hdr:add(f.len, len)
	if (len:uint() == 0xFF) then
		local extlen = buffer(offset + 4, 2);
		hdr:add(f.extlen, extlen)
		hdr:add(f.data, buffer(offset + 6, extlen:uint()))
		offset = offset + 6 + extlen:uint()
	elseif (len:uint() > 0) then
		hdr:add(f.data, buffer(offset + 4, len:uint()))
		offset = offset + 4 + len:uint()
	else
		offset = offset + 4
	end
	
	hdr:add(f.crc, buffer(offset, 1))
	
	return offset + 1
end

function xsens_proto.dissector(buffer, pinfo, tree)
	local offset = 0;
	local count = 0;
	local t;

	if (buffer:len() < 5) then
		return
	end

	if (buffer(0,2):uint() ~= 0xFAFF) then
		return
	end

	t = tree:add(xsens_proto, buffer(offset))

	repeat
		if (buffer(offset,2):uint() == 0xFAFF) then
			offset = parsesingle(buffer,offset,pinfo,tree,t)
			count = count + 1;
		else
			offset = offset + 1
		end
	until (offset + 5) >= buffer:len()
	
	pinfo.cols['protocol'] = pinfo.curr_proto
	pinfo.cols['info'] = string.format("chunk of %d packets",count)
end

usb_devs = DissectorTable.get("usb.product")
usb_devs:add(0x26390017,xsens_proto)

-- register_postdissector(xsens_proto)