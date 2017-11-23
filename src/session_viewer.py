
from scapy.all import *
from scapy.contrib.skinny import *

from common_types import SessionBase, SessionIterator


class SessionViewer(SessionIterator):

    def process_msg(self, sccp_msg, fdir, pkt_time):
        # print "[SessionViewer::process_msg] msg: %s, len: %s + 12 bytes, ver.: %s" % (
        #     hex(sccp_msg.msg), sccp_msg.len, sccp_msg.res)

        if sccp_msg.msg == 0x14a:

            if sccp_msg.haslayer(Raw):
                raise ValueError("msg '%s' (%s + 12 bytes) has RAW data" % (skinny_messages_cls[sccp_msg.msg], sccp_msg.len))

            #
            # Do custom packet inspection
            #
            sub_msg = sccp_msg[SkinnyMessageCM5CallInfo]
            if sub_msg.calltype == 3:
                print "FOUND forward(3) CM5 info: callid: %s" % sub_msg.callid
