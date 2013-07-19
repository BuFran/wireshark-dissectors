xsens_proto = Proto("xsens", "Xsens MTi Protocol")

-- enum

vs_mid = {
	[0x00] = "ReqDeviceID",
	[0x01] = "DeviceID",
	[0x02] = "InitMT",
	[0x03] = "InitMTResults",
	[0x04] = "ReqPeriod",
	[0x05] = "Period",

	[0x0a] = "ReqDataLength",
	[0x0b] = "DataLength",
	[0x0c] = "ReqConfiguration",
	[0x0d] = "Configuration",
	[0x0e] = "RestoreFactoryDef",
	[0x0f] = "RestoreFactoryDefAck",
	[0x10] = "GoToMeasurement",
	[0x11] = "GoToMeasurementAck",
	[0x12] = "ReqFirmwareRev",
	[0x13] = "FirmwareRev",
	[0x18] = "ReqBaudrate",
	[0x19] = "Baudrate",
	[0x1c] = "ReqProductCode",
	[0x1d] = "ProductCode",
	[0x20] = "ReqProcessingFlags",
	[0x21] = "ProcessingFlags",
	[0x22] = "SetNoRotation",
	[0x23] = "SetNoRotationAck",
	[0x24] = "RunSelftest",
	[0x25] = "RunSelftestAck",
	[0x2c] = "ReqSyncSettings",
	[0x2d] = "SyncSettings",

	[0x30] = "GoToConfig",
	[0x31] = "GoToConfigAck",
	[0x32] = "MTData",
	[0x34] = "ReqData",
	[0x35] = "ReqDataAck",
	[0x36] = "MTData2",
	[0x3e] = "WakeUp",
	[0x3f] = "WakeUpAck",
	[0x40] = "Reset",
	[0x41] = "ResetAck",
	[0x42] = "Error",

	[0x60] = "ReqUTCTime",
	[0x61] = "UTCTime",
	[0x62] = "ReqAvailableScenarios",
	[0x63] = "AvailableScenarios",
	[0x64] = "ReqCurrentScenario",
	[0x65] = "CurrentScenario",
	[0x66] = "ReqGravityMagnitude",
	[0x67] = "GravityMagnitude",
	[0x68] = "ReqLeverArmGPS",
	[0x69] = "LeverArmGPS",
	[0x6a] = "ReqMagneticDeclination",
	[0x6b] = "MagneticDeclination",
	[0x6e] = "ReqLatLonAlt",
	[0x6f] = "LatLonAlt",

	[0x82] = "ReqHeading",
	[0x83] = "Heading",
	[0x84] = "ReqLocationID",
	[0x85] = "LocationID",
	[0x86] = "ReqExtOutputMode",
	[0x87] = "ExtOutputMode",
	[0x8a] = "StoreFilterState",
	[0x8b] = "StoreFilterStateAck",

	[0x90] = "ReqEMTS",
	[0x91] = "EMTSData",
	[0x94] = "RestoreEMTS",
	[0x95] = "RestoreEMTSAck",
	[0x96] = "StoreEMTS",
	[0x97] = "StoreEMTSAck",

	[0xa4] = "ResetOrientation",
	[0xa5] = "ResetOrientationAck",
	[0xa6] = "ReqGPSStatus",
	[0xa7] = "GPSStatus",

	[0xc0] = "ReqOutputConfiguration",
	[0xc1] = "OutputConfiguration",

	[0xd0] = "ReqOutputMode",
	[0xd1] = "OutputMode",
	[0xd2] = "ReqOutputSettings",
	[0xd3] = "OutputSettings",
	[0xd4] = "ReqOutputSkipFactor",
	[0xd5] = "OutputSkipFactor",
	[0xd6] = "ReqSyncInSettings",
	[0xd7] = "SyncInSettings",
	[0xd8] = "ReqSyncOutSettings",
	[0xd9] = "SyncOutSettings",
	[0xda] = "ReqErrorMode",
	[0xdb] = "ErrorMode",
	[0xdc] = "ReqTransmitDelay",
	[0xdd] = "TransmitDelay",

	[0xe0] = "ReqObjectAlignment",
	[0xe1] = "ObjectAlignment"
}

local f = xsens_proto.fields

-- header
f.preamble = ProtoField.uint8("xsens.preamble", "Preamble", base.HEX)
f.bid = ProtoField.uint8("xsens.bid", "Bus ID", base.HEX)
f.mid = ProtoField.uint8("xsens.mid", "Message ID", base.HEX, vs_mid)
f.len = ProtoField.uint8("xsens.len", "Length", base.DEC)
f.extlen = ProtoField.uint16("xsens.extlen", "Ext Length", base.DEC)
f.data = ProtoField.bytes("xsens.data", "Data")
f.crc = ProtoField.uint8("xsens.crc", "Checksum", base.HEX)

function parsesingle(buffer,offset,pinfo, tree,t)
	local len = buffer(offset + 3, 1)
	local mid = buffer(offset + 2, 1)
	local extlen, data, length, hdr
	
	if (len:uint() == 0xFF) then
		extlen = buffer(offset + 4, 2)
		data = buffer(offset + 6, extlen:uint())
		length = 7 + extlen:uint()
	elseif (len:uint() > 0) then
		length = 5 + len:uint()
		data = buffer(offset + 4, len:uint())
	else
		length = 5
	end

	if data then
		hdr = t:add(buffer(offset, length), vs_mid[mid:uint()].." : "..tostring(data))
	else
		hdr = t:add(buffer(offset, length), vs_mid[mid:uint()])
	end
	hdr:add(f.mid, mid)
	hdr:add(f.len, len)
	hdr:add(f.crc, buffer(offset+length - 1, 1))
	
	if extlen then hdr:add(f.extlen, extlen) end
	if data then 
		hdr = hdr:add(f.data, data)
		if (mid:uint() == 0x36) then
			local o = data:offset();
			local e = data:offset() + data:len();
			repeat
				local id = buffer(o,2)
				local lgt = buffer(o+2,1)
				data = buffer(o+3,lgt:uint())
				hdr:add(data, string.format("0x%04x : %s",id:uint(),tostring(data)))
				o = o + lgt:uint() + 3
			until o >= e
		end
	end

	return offset + length
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
	until (offset + 5) > buffer:len()
	
	pinfo.cols['protocol'] = pinfo.curr_proto
	pinfo.cols['info'] = string.format("chunk of %d packets",count)
end

usb_devs = DissectorTable.get("usb.product")
usb_devs:add(0x26390017,xsens_proto)

-- register_postdissector(xsens_proto)