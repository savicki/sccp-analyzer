
# -*- coding: windows-1252 -*-

from scapy.all import *
from scapy.contrib.skinny import *

import binascii, sys, os



Skinny = scapy.contrib.skinny.Skinny

tcp = TCP(sport=1024, dport=2000);

print tcp.summary()

#tcp.do_dissect_payload('\x14\x00\x00\x00\x12\x00\x00\x00\x85\x00\x00\x00\x01\x00\x00\x00\x01\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')

# SoftKeyEvent, NewCall(2) from CCM
tcp.do_dissect_payload(binascii.unhexlify('100000001200000026000000020000000000000000000000'))
print tcp.summary()
print
# print isinstance(tcp[Skinny][SkinnyMessageSoftKeyEvent], scapy.contrib.skinny.SkinnyMessageSoftKeyEvent)


sccp = tcp[Skinny]
sccp_msg = sccp[scapy.contrib.skinny.SkinnyMessageSoftKeyEvent]
#print sccp_msg
#print str(tcp[Skinny][SkinnyMessageSoftKeyEvent]).encode("HEX")
sccp_msg.show()
print


# SkinnyMessageEnblocCall
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('20000000120000000400000033323832000000000000000000000000000000000000000001000000'))
tcp[Skinny].show()
print


# SkinnyMessageDialedNumber
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('24000000120000001d01000033323832000000000000000000000000000000000000000001000000c43d5801'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageCallState
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('1c00000012000000110100000c00000001000000c43d5801000000000400000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageTimeDate
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('280000001200000094000000e10700000900000005000000080000000e000000190000001500000000000000217eb259'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageCM5CallInfo
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('84000000120000004a01000001000000794d580101000000000000000000000001000000000000000000000033323832003332383200353335330035333533003533353300000000004c656f6e6f76204f6c6567004d616e64726f7620416c656b73616e6472004d616e64726f7620416c656b73616e6472004d616e64726f7620416c656b73616e64720000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageCM5CallInfo
# outbound
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('74000000120000004a0100000100000027525801020000000000000000000000010000000000000000000000353335330000333238320033323832003332383200000000004d616e64726f7620416c656b73616e6472004c656f6e6f76204f6c6567004c656f6e6f76204f6c6567004c656f6e6f76204f6c65670000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# inbound
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('88000000120000004a010000010000009666690101000000000000000000000001000000000000000000000035333533003533353300353539380035353938003535393800000000004d616e64726f7620416c656b73616e6472004b6f6c67616e6f76612059756c697961004b6f6c67616e6f76612059756c697961004b6f6c67616e6f76612059756c697961000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# inbound
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('88000000120000004a0100000100000051676901010000000000000000000000010000000000000000000000353134340035313434003534363200353436320035343632000000000043686170636861657620416e6472657900566173696c79657620416c656b73657900566173696c79657620416c656b73657900566173696c79657620416c656b73657900000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageCallState
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('1c00000012000000110100000c0000000100000027525801000000000400000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageConnectionStatisticsRes
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('b40000001200000023000000353335330000000000000000000000000000000000000000794d580100000000a502000020a70100a6020000c0a701000000000000000000000000006e0000004d4c514b3d302e303030303b4d4c514b61763d302e303030303b4d4c514b6d6e3d302e303030303b4d4c514b6d783d302e303030303b4943523d302e303030303b4343523d302e303030303b4943526d783d302e303030303b43533d303b5343533d303b4d4c514b76723d302e300000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageLineStatV2
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('2800000012000000470100000100000009000000333234310033323431004976616e74736f7661204f6c676100000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageLineStatV2
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('100000001200000047010000020000000000000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageRegister
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('8000000000000000010000004976616e74736f76614f59000000000000000000000000000a0065d040750000050000000000000014007285010000000000000031633162206433353961623703000000240000000000000000000000000000000000000000000000434950432d382d362d362d300000000000000000000000000000000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageRegisterAck
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('1800000000000000810000001e0000004d2d442d590000003c0000001220f1ff'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageLineStatReq
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('08000000120000000b00000002000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageOffHook
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('0c00000012000000060000000000000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# ConnectionStatRes (180/0x6f)
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('b40000001100000023000000333931300000000000000000000000000000000000000000646f5a0100000000dd0000007c940000c6000000088500000000000007000000000000006f0000004d4c514b3d302e303030303b4d4c514b61763d302e303030303b4d4c514b6d6e3d302e303030303b4d4c514b6d783d302e303030303b4943523d302e303431363b4343523d302e303431363b4943526d783d302e303431363b43533d333b5343533d313b4d4c514b76723d302e393500'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# ConnectionStatRes (180/0x70)
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('b40000001100000023000000333931300000000000000000000000000000000000000000d2c45a010000000057a3000074be6d0043a3000004b16d00010000000300000000000000700000004d4c514b3d342e343433383b4d4c514b61763d342e343435333b4d4c514b6d6e3d332e383336313b4d4c514b6d783d342e353030303b4943523d302e303030303b4343523d302e303031343b4943526d783d302e303633353b43533d34373b5343533d353b4d4c514b76723d302e3935'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# ConnectionStatRes (184/0x72)
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('b80000001100000023000000333931300000000000000000000000000000000000000000fecf5a0100000000daa20200786ac501bfa202005458c5010c0000000200000000000000720000004d4c514b3d342e333832383b4d4c514b61763d342e343337353b4d4c514b6d6e3d332e373739353b4d4c514b6d783d342e353030303b4943523d302e303030303b4343523d302e303031353b4943526d783d302e303636343b43533d3235313b5343533d31353b4d4c514b76723d302e39350000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print




# OpenReceiveChannelAck v18
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('2800000012000000220000000000000000000000140003ad00000000000000000000000000600000ac1eab01a2e75901'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print

# OpenReceiveChannelAck v0
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('180000000000000022000000000000001400036000600000882dab0128fd5901'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# OpenReceiveChannelAck v17
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('28000000110000002200000000000000000000000a006c65000000000000000000000000e24900006587ab01f3905a01'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print




# SMT v18
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('88000000120000008a000000a2e75901ac1eab01000000000a0003070000000000000000000000004c4200001400000002000000b8000000000000000000000000000000a2e759010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SMT v0
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('78000000000000008a00000028fd5901882dab010a006a03247e00001400000002000000b800000000000000000000000000000028fd59010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000650000000a0000000000000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SMT v17
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('88000000110000008a000000f3905a016587ab01000000000a006c03000000000000000000000000324300001400000004000000b8000000000000000000000000000000f3905a010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print




# SMTa v18
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('2c0000001200000054010000a2e75901ac1eab01a2e75901000000000a0002400000000000000000000000000000000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SMTa v0
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('1c000000000000005401000028fd5901882dab0128fd59010a006a0c0000000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SMTa v17
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('2c0000001100000054010000f3905a016587ab01f3905a01000000000a006c65000000000000000000000000e249000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print




# ORC v18
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('840000001200000005010000a2e75901ac1eab0114000000020000000000000000000000a2e759010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000a000307000000000000000000000000a00f000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# ORC v0
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('70000000000000000501000028fd5901882dab011400000002000000000000000000000028fd59010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000650000000a00000000000000000000000a006a03a00f0000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# ORC v17
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('840000001100000005010000f3905a016587ab0114000000040000000000000000000000f3905a010000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000a0000000000000000000000000000000a006c03000000000000000000000000a00f000000000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print



# CloseReceiveChannel
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('140000001100000006010000f3905a016587ab01f3905a0100000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# StopMediaTransmission
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('14000000110000008b000000f3905a016587ab01f3905a0100000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


# SkinnyMessageCM5CallInfo
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('70000000110000004a0100000100000002975a010200000000000000020000000100000001000000280000003332323400000035313633003531363300000000004d656574696e6720696e20556661008034004d656574696e6720526f6f6d20544443004d656574696e6720526f6f6d2054444300000000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


sccp = tcp[Skinny]
# this works - convert win-1251 bytes to string, then back to utf-8 bytes and print them
print sccp.originalcalledpartyname.decode('windows-1252').encode('utf-8')


SkinnyMessageCM5CallInfo
tcp.remove_payload()
tcp.do_dissect_payload(binascii.unhexlify('80000000110000004a0100000100000002975a01020000000000000000000000010000000100000000000000333232340000353136330035313633003531363300000000004d656574696e6720696e20556661004d656574696e6720526f6f6d20544443004d656574696e6720526f6f6d20544443004d656574696e6720526f6f6d205444430000'))
tcp[Skinny].show()
print '**** failed dissect some data: RAW' if tcp[Skinny].haslayer(Raw) else ''
print


#print str(tcp).encode("HEX")

#print tcp.summary()

# tcp.do_dissect_payload( binascii.unhexlify('100000001200000086000000090000000100000002000000') )
# print tcp.summary()
# tcp.show()


# print sys.getdefaultencoding()
#print sys.stdout.encoding

# os.putenv('PYTHONIOENCODING', 'utf8')

# str(u"\u20AC")
# unicode("€")
#print "{}".format(u"\u20AC")

# print b'\x34'.decode('windows-1252')

# arr = b'\x80\x34\x00'.decode('windows-1252').encode('utf-8').decode('windows-1252')
# print b'\x80\x34\x00'


#print '€'.encode('utf-8')