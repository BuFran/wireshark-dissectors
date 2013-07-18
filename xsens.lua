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

	-- Add the header tree item and populate it
	local hdr = t:add(buffer(offset, length), string.format("PACKET MID=0x%02x LEN=%d",mid:uint(),length))
	--  hdr:add(f.preamble, buffer(offset + 0, 1))
	--  hdr:add(f.bid, buffer(offset + 1, 1))
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
	
	while (offset + 1) < buffer:len() do
		if (buffer(offset,2):uint() == 0xFAFF) then
			if (t == nil) then
				pinfo.cols['protocol'] = pinfo.curr_proto
				t = tree:add(xsens_proto, buffer(offset))
			end
			
			offset = parsesingle(buffer,offset,pinfo,tree,t)
			count = count + 1;
		else
			offset = offset + 1
		end
	end
	
	if (count > 0) then
		pinfo.cols['info'] = string.format("chunk of %d packets",count)
	end
end


-- DissectorTable.get("usb.bulk"):add(xsens_proto)

usb_devs = DissectorTable.get("usb.product")
usb_devs:add(0x26390017,xsens_proto)

-- register_postdissector(xsens_proto)