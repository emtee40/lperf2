--
-- Wireshark dissector for iperf2.1.9
-- Currently supports basic UDP test cases
-- To install, copy this file to wireshark's dissector search path
--
-- Original Author reference (2.0.5 version):
-- http://www.ainoniwa.net/ssp/wp-content/uploads/2013/06/wireshark_dissector_with_lua.pdf
--
-- https://sourceforge.net/projects/iperf2/
--

local iperf_proto = Proto("iperf","Iperf UDP packet")
local iperf_seq_F = ProtoField.uint32("iperf.id", "Iperf sequence")
local iperf_time_F = ProtoField.string("iperf.ts", "Iperf TimeStamp")
local iperf_sec_F = ProtoField.uint32("iperf.sec", "Iperf sec")
local iperf_usec_F = ProtoField.uint32("iperf.usec", "Iperf usec")
local iperf_seq2_F = ProtoField.uint32("iperf.id2", "Iperf sequence extended")
local iperf_flags_F = ProtoField.uint32("iperf.flags", "Iperf flags", base.HEX)
local iperf_numthreads_F = ProtoField.int32("iperf.numThreads", "Iperf numThreads")
local iperf_mport_F = ProtoField.int32("iperf.mPort", "Iperf mPort")
local iperf_bufferlen_F = ProtoField.int32("iperf.bufferlen", "Iperf bufferlen")
local iperf_mwinband_F = ProtoField.int32("iperf.mWinBand", "Iperf mWinBand")
local iperf_mamount_F = ProtoField.int32("iperf.mAmount", "Iperf mAmount")
local iperf_type_F = ProtoField.int32("iperf.type", "Iperf type")
local iperf_length_F = ProtoField.int32("iperf.length", "Iperf length")
local iperf_upperflags_F = ProtoField.uint16("iperf.upperflags", "Iperf upperflags", base.HEX)
local iperf_lowerflags_F = ProtoField.uint16("iperf.lowerflags", "Iperf lowerflags", base.HEX)
local iperf_version_u_F = ProtoField.uint32("iperf.version_u", "Iperf version_u", base.HEX)
local iperf_version_l_F = ProtoField.uint32("iperf.version_l", "Iperf version_l", base.HEX)
local iperf_reserved_F = ProtoField.uint16("iperf.reserved", "(reserved)")
local iperf_tos_F = ProtoField.uint16("iperf.tos", "Iperf tos", base.HEX)
local iperf_irate_F = ProtoField.uint32("iperf.irate", "Iperf irate")
local iperf_urate_F = ProtoField.uint32("iperf.urate", "Iperf urate")
local iperf_tcpwriteprefetch_F = ProtoField.uint32("iperf.tcpwriteprefetch", "Iperf tcpwriteprefetch")

iperf_proto.fields = {
   iperf_seq_F, iperf_time_F, iperf_sec_F, iperf_usec_F, iperf_seq2_F,
   iperf_flags_F, iperf_numthreads_F, iperf_mport_F,
   iperf_bufferlen_F, iperf_mwinband_F, iperf_mamount_F, iperf_type_F,
   iperf_length_F, iperf_upperflags_F, iperf_lowerflags_F,
   iperf_version_u_F, iperf_version_l_F, iperf_reserved_F, iperf_tos_F,
   iperf_irate_F, iperf_urate_F, iperf_tcpwriteprefetch_F
}

function iperf_proto.dissector(buffer,pinfo,tree)

 local iperf_seq_range = buffer(0,4)
 local iperf_time_range = buffer(4,8)
 local iperf_sec_range = buffer(4,4)
 local iperf_usec_range = buffer(8,4)
 local iperf_seq2_range = buffer(12,4)
 local iperf_flags_range = buffer(16,4)
 local iperf_numthreads_range = buffer(20,4)
 local iperf_mport_range = buffer(24,4)
 local iperf_bufferlen_range = buffer(28,4)
 local iperf_mwinband_range = buffer(32,4)
 local iperf_mamount_range = buffer(36,4)
 local iperf_type_range = buffer(40,4)
 local iperf_length_range = buffer(44,4)
 local iperf_upperflags_range = buffer(48,2)
 local iperf_lowerflags_range = buffer(50,2)
 local iperf_version_u_range = buffer(52,4)
 local iperf_version_l_range = buffer(56,4)
 local iperf_reserved_range = buffer(60,2)
 local iperf_tos_range = buffer(62,2)
 local iperf_irate_range = buffer(64,4)
 local iperf_urate_range = buffer(68,4)
 local iperf_tcpwriteprefetch_range = buffer(72,4)

 local iperf_seq = iperf_seq_range:uint()
 local iperf_sec = iperf_sec_range:uint()
 local iperf_usec = iperf_usec_range:uint()
 local iperf_seq2 = iperf_seq2_range:uint()
 local iperf_flags = iperf_flags_range:int()
 local iperf_numthreads = iperf_numthreads_range:int()
 local iperf_mport = iperf_mport_range:int()
 local iperf_bufferlen = iperf_bufferlen_range:int()
 local iperf_mwinband = iperf_mwinband_range:int()
 local iperf_mamount = iperf_mamount_range:int()
 local iperf_type = iperf_type_range:int()
 local iperf_length = iperf_length_range:int()
 local iperf_upperflags = iperf_upperflags_range:int()
 local iperf_lowerflags = iperf_lowerflags_range:int()
 local iperf_version_u = iperf_version_u_range:int()
 local iperf_version_l = iperf_version_l_range:int()
 local iperf_reserved = iperf_reserved_range:int()
 local iperf_tos = iperf_tos_range:int()
 local iperf_irate = iperf_irate_range:int()
 local iperf_urate = iperf_urate_range:int()
 local iperf_tcpwriteprefetch = iperf_tcpwriteprefetch_range:int()

 -- Work out the timestamp from the sec and usec
 local timestamp = (iperf_sec * 1.0) + (iperf_usec / 1000000.0)
 local iperf_time = format_date(timestamp)

 local subtree = tree:add(iperf_proto, buffer(0,76), "Iperf packet data")
 subtree:add(iperf_seq_F, iperf_seq_range, iperf_seq)
 timetree = subtree:add(iperf_time_F, iperf_time_range, iperf_time)
 timetree:add(iperf_sec_F, iperf_sec_range, iperf_sec)
 timetree:add(iperf_usec_F, iperf_usec_range, iperf_usec)
 subtree:add(iperf_seq2_F, iperf_seq2_range, iperf_seq2)
 subtree:add(iperf_flags_F, iperf_flags_range, iperf_flags)
 subtree:add(iperf_numthreads_F, iperf_numthreads_range, iperf_numthreads)
 subtree:add(iperf_mport_F, iperf_mport_range, iperf_mport)
 subtree:add(iperf_bufferlen_F, iperf_bufferlen_range, iperf_bufferlen)
 subtree:add(iperf_mwinband_F, iperf_mwinband_range, iperf_mwinband)
 subtree:add(iperf_mamount_F, iperf_mamount_range, iperf_mamount)
 subtree:add(iperf_type_F, iperf_type_range, iperf_type)
 subtree:add(iperf_length_F, iperf_length_range, iperf_length)
 subtree:add(iperf_upperflags_F, iperf_upperflags_range, iperf_upperflags)
 subtree:add(iperf_lowerflags_F, iperf_lowerflags_range, iperf_lowerflags)
 subtree:add(iperf_version_u_F, iperf_version_u_range, iperf_version_u)
 subtree:add(iperf_version_l_F, iperf_version_l_range, iperf_version_l)
 subtree:add(iperf_reserved_F, iperf_reserved_range, iperf_reserved)
 subtree:add(iperf_tos_F, iperf_tos_range, iperf_tos)
 subtree:add(iperf_irate_F, iperf_irate_range, iperf_irate)
 subtree:add(iperf_urate_F, iperf_urate_range, iperf_urate)
 subtree:add(iperf_tcpwriteprefetch_F, iperf_tcpwriteprefetch_range, iperf_tcpwriteprefetch)

Dissector.get("data"):call(buffer(76,buffer:len()-76):tvb(), pinfo, tree)
end
DissectorTable.get("udp.port"):add("5001-5039", iperf_proto)
