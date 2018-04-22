import sys
import hashlib
import binascii
from scapy.all import TCP, scapy

from common_types import InspectAction, Dir, get_dir, PacketState
from constants import SCCP_PORT

Skinny = scapy.contrib.skinny.Skinny
# Skinny = scapy.layers.skinny.Skinny


def hash_session(p):
    sess = "Other"
    if 'Ether' in p:
        if 'IP' in p:
            if 'TCP' in p:
                if p[TCP].dport == SCCP_PORT:
                    sess = p.sprintf(
                        "TCP %IP.src%:%r,TCP.sport% -- "
                        "%IP.dst%:%r,TCP.dport%")
                elif p[TCP].sport == SCCP_PORT:
                    sess = p.sprintf(
                        "TCP %IP.dst%:%r,TCP.dport% -- "
                        "%IP.src%:%r,TCP.sport%")
                else:
                    sess = p.sprintf(
                        "TCP %IP.src%:%r,TCP.sport% > "
                        "%IP.dst%:%r,TCP.dport%")
            else:
                sess = p.sprintf(
                    "IP %IP.src% > "
                    "%IP.dst% proto=%IP.proto%")
        else:
            sess = p.sprintf("Ethernet type=%04xr,Ether.type%")
    # print sess
    return sess


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


def __inspect_pkt(pkt, fdir, pkt_state):
    pass
    # mask = PacketState.PartialEnd | \
    #         PacketState.OneOfMultiple | \
    #         PacketState.WithPriorInjects
    # mask = PacketState.Single

    # if (pkt_state & mask != 0):
    #   print '[{} dir: {}] {} tcp_len: {} msg_len: {} id: {}'.format(
    #       int(pkt_state),
    #       fdir,
    #       pkt.summary(),
    #       len(pkt[TCP].payload),
    #       pkt[TCP][Skinny].len + 8,
    #       hex(pkt[TCP][Skinny].msg)
    #   )
    #   print


class ProcessingStats(object):
    def __init__(self):
        self.pkts_total = 0
        self.pkts_empty = 0
        self.msgs_single = 0
        # 2 partial msg frags => 1 complete msg
        self.msgs_frags = 0
        self.msgs_fat = 0
        self.msgs_injected = 0

    def __str__(self):
        return 'total:{} empty:{} single:{} frgs:{} fat:{} inj:{}'.format(
            self.pkts_total,
            self.pkts_empty,
            self.msgs_single,
            self.msgs_frags,
            self.msgs_fat,
            self.msgs_injected)


class DirInfo(object):
    def __init__(self):
        self.stats = ProcessingStats()
        # part of sccp msg
        self.cached_payload = []  # TODO: cache limit
        # TCP pkt without payload
        self.cached_pkt = None
        self.bytes_needed = 0
        self.zero_bytes = 0


def __print_sccp_packet(pkt, prefix=''):
    if len(pkt[TCP].payload) > 0:
        # print len(tcp.payload)
        # print '\n'
        # print len(tcp)
        # tcp.show()

        # sccp = pkt/TCP()/Skinny()

        tcp = pkt[TCP]
        sccp = tcp[Skinny]
        # sccp.show()
        # print str(sccp).encode("HEX")
        # print hex(sccp.msg), sccp.len, sccp.res
        if sccp.len + 8 != len(pkt[TCP].payload):
            print str(tcp.payload).encode("HEX")
            # print type(tcp.payload) is str
            # print
            # print str(tcp.payload.payload).encode("HEX")

            if isinstance(tcp.payload, Skinny):
                print tcp.payload.summary()

            # print
            # print str(pkt/TCP()/Skinny().payload).encode("HEX")
            # print
            # print str(sccp.payload).encode("HEX")
            print "%s[%s] : (msg_id: %s, msg_len: %s, msg_ver: %s)"\
                  " [%s bytes]" % (
                        prefix, pkt.time, hex(sccp.msg), sccp.len + 8,
                        sccp.res, len(pkt[TCP].payload))
    # else:
    #   print '%s[%s] : ' % (prefix, pkt.time)


def __str_to_bytes(str):
    n = 2
    return [str[i:i+n] for i in range(0, len(str), n)]


def __get_bytes(bytes, st_ind, end_ind_exl=None):
    return ''.join(bytes[st_ind:end_ind_exl])


def __inspect_msg(pkt, fdir, session_info, callback):
    action = InspectAction.No
    inject_pkts = []
    dir_info = session_info[fdir]

    tcp = pkt[TCP]
    tcp_len = len(tcp.payload) if isinstance(tcp.payload, Skinny) else 0
    orig_tcp_len = tcp_len

    # print "[__inspect_msg] pkt_num: %s, tcp_len: %s, is skinny: %s" %
    #        (pkt_num, tcp_len, isinstance(tcp.payload, Skinny))

    dir_info.stats.pkts_total += 1

    if tcp_len == 0:
        dir_info.stats.pkts_empty += 1
        # print "exit 0 len"
    else:
        # initial tcp payload size
        bytes_avail = tcp_len

        while bytes_avail > 0:
            # print "bytes_needed = %s" % dir_info.bytes_needed

            if dir_info.bytes_needed == 0:  # e.g. '1' or '1/2 + 1'
                # print len(tcp.payload), bytes_avail
                sccp = tcp[Skinny]
                # sizeof single sccp message
                # don't trust @sccp.len as is --
                # it may point to value somewhere in non-sccp-header
                sccp_len = sccp.len + 8

                # print "[__inspect_msg] tcp_len: %s, sccp_len: %s" %
                #        (tcp_len, sccp_len)

                # e.g. 8x "\x00" bytes
                if sccp.len == 0:

                    sys.stderr.write(
                        "[__inspect_msg] bogus sccp_len: %s\n" % sccp.len)

                    action |= InspectAction.EmptyBytes
                    bytes_avail -= 4
                    dir_info.zero_bytes += 4

                    tcp_payload_bytes = __str_to_bytes(
                        str(tcp.payload).encode("HEX"))
                    tcp.remove_payload()

                    tcp_payload = __get_bytes(tcp_payload_bytes, 4)
                    tcp.do_dissect_payload(binascii.unhexlify(tcp_payload))

                    tcp_len = len(tcp.payload)

                    # print "[__inspect_msg] new tcp_len: %s" % (tcp_len)
                    continue

                elif sccp.len % 4 != 0:

                    sys.stderr.write(
                        "[__inspect_msg] [pkt.time: %s] "
                        "[tcp.len: %s] unaligned sccp_len: %s, exit\n" %
                        (pkt.time, orig_tcp_len, sccp.len))

                    action |= InspectAction.Error
                    break

                # two length fields magically match - let trust
                if tcp_len == sccp_len:  # e.g. ^1^ + '1'
                    # one pkt - one msg, nice
                    dir_info.stats.msgs_single += 1

                    bytes_avail -= tcp_len

                    action |= InspectAction.Pass

                    callback(pkt,
                             fdir, PacketState.Single |
                             (0 if len(inject_pkts) == 0 else
                              PacketState.WithPriorInjects))

                # more data required - msg spread over pkt
                elif sccp_len > bytes_avail:  # e.g. ^1^ + '1/2'

                    # print "[__inspect_msg] sccp_len: %s > bytes_avail: %s" %
                    #       (sccp_len, bytes_avail)

                    dir_info.cached_payload.append(
                        str(tcp.payload).encode("HEX"))
                    tcp.remove_payload()

                    dir_info.bytes_needed = sccp_len - bytes_avail
                    dir_info.cached_pkt = pkt.copy()

                    bytes_avail = 0

                    dir_info.stats.msgs_frags += 1

                    action &= ~InspectAction.Pass

                    # callback(pkt, fdir, PacketState.PartialBegin |
                    #   0 if len(inject_pkts) == 0 else
                    #   PacketState.WithPriorInjects)

                # pkt contains 1+ msg(s)
                elif sccp_len < tcp_len:  # e.g. ^1^ + '1+1/2'
                    # print '[%s] : tcp_len: %s, sccp_len: %s @ %s, csum: %s' %
                    #    (fdir, tcp_len, sccp_len, pkt.time, hex(tcp.chksum))

                    tcp_payload_bytes = __str_to_bytes(
                        str(tcp.payload).encode("HEX"))
                    tcp.remove_payload()

                    inject_pkt = pkt.copy()
                    tcp_payload = __get_bytes(tcp_payload_bytes, 0, sccp_len)
                    inject_pkt[TCP].do_dissect_payload(
                        binascii.unhexlify(tcp_payload))
                    inject_pkts_len = len(inject_pkts)
                    inject_pkts.append(inject_pkt)

                    bytes_avail -= sccp_len
                    action |= InspectAction.InjectBefore

                    remain_payload = __get_bytes(tcp_payload_bytes, sccp_len)
                    tcp.do_dissect_payload(binascii.unhexlify(remain_payload))
                    tcp_len = len(tcp.payload)

                    dir_info.stats.msgs_fat += 1
                    dir_info.stats.msgs_injected += 1

                    callback(inject_pkt, fdir, PacketState.OneOfMultiple |
                             (0 if inject_pkts_len == 0 else
                              PacketState.WithPriorInjects))

                    # print inject_pkts_len, \
                    #   (PacketState.OneOfMultiple | \
                    #   (0 if inject_pkts_len == 0 else \
                    #       PacketState.WithPriorInjects))

            # dir_info.bytes_needed != 0
            else:
                # there are enough bytes to complete cached msg
                # e.g. (1/2) + '1/2' , (1/2) + '1/2 + 1' , (1/2) + '1/2 + 1/2'
                if bytes_avail >= dir_info.bytes_needed:

                    cached_payload = ''.join(dir_info.cached_payload)

                    tcp_payload_bytes = __str_to_bytes(
                        str(tcp.payload).encode("HEX"))
                    tcp.remove_payload()

                    needed_payload = __get_bytes(
                        tcp_payload_bytes, 0, dir_info.bytes_needed)

                    # e.g. (1/2) + '1/2'
                    if bytes_avail == dir_info.bytes_needed:
                        inject_pkt = pkt
                        action |= InspectAction.Pass
                    else:  # e.g. (1/2) + '1/2 + 1'
                        inject_pkt = dir_info.cached_pkt
                        inject_pkts.append(inject_pkt)
                        action |= InspectAction.InjectBefore

                        # pkt contains next msg(s)
                        remain_payload = __get_bytes(
                            tcp_payload_bytes, dir_info.bytes_needed)

                        tcp.do_dissect_payload(
                            binascii.unhexlify(remain_payload))

                        tcp_len = len(tcp.payload)

                    # test stream damage and csum failure
                    # needed_payload = '1' + needed_payload[1:]

                    inject_pkt[TCP].do_dissect_payload(
                        binascii.unhexlify(cached_payload + needed_payload))
                    dir_info.stats.msgs_injected += 1

                    callback(pkt, fdir, PacketState.PartialEnd)

                    bytes_avail -= dir_info.bytes_needed
                    dir_info.bytes_needed = 0
                    dir_info.cached_pkt = None
                    dir_info.cached_payload = []

                # msg continuation, add to cache and drop pkt --
                # still need more data
                else:  # e.g. ^1/3^ + '1/3'
                    dir_info.cached_payload.append(
                        str(tcp.payload).encode("HEX"))

                    dir_info.bytes_needed -= bytes_avail
                    bytes_avail = 0

                    dir_info.stats.msgs_frags += 1

                    action &= ~InspectAction.Pass

    return action, inject_pkts


def get_msg_flow(pkt_flow):

    msg_flow_acc = {
        Dir.DIR_ORIG: DirInfo(),
        Dir.DIR_REPLY: DirInfo()
    }
    msg_flow = []
    stream_errors = InspectAction.No

    bytes_len_before = 0
    bytes_len_after = 0
    orig_hash = hashlib.sha256()
    mod_hash = hashlib.sha256()

    if len(pkt_flow) > 0:
        st_time = pkt_flow[0].time
        end_time = pkt_flow[len(pkt_flow) - 1].time
    else:
        st_time = 0
        end_time = 0

    for pkt in pkt_flow:

        bytes_len_before += len(pkt[TCP].payload)
        orig_hash.update(str(pkt[TCP].payload).encode("HEX"))

        # __print_sccp_packet(pkt, get_dir(pkt.dport))

        # print "\n[get_msg_flow] [in] pkt.len: %s" % len(pkt[TCP].payload)

        act, inject_pkts = __inspect_msg(
            pkt, get_dir(pkt.dport), msg_flow_acc, __inspect_pkt)

        stream_errors |= act

        # print "[get_msg_flow] [out] act: %s,inject_pkts: %s,pkt.len: %s\n" %
        #        (act, len(inject_pkts), len(pkt[TCP].payload))

        if (act & InspectAction.InjectBefore):
            for inject_pkt in inject_pkts:
                msg_flow.append(inject_pkt)

                bytes_len_after += len(inject_pkt[TCP].payload)
                mod_hash.update(str(inject_pkt[TCP].payload).encode("HEX"))

        if (act & InspectAction.Error):
            break

        elif (act & InspectAction.Pass):
            msg_flow.append(pkt)

            bytes_len_after += len(pkt[TCP].payload)
            mod_hash.update(str(pkt[TCP].payload).encode("HEX"))

    if (stream_errors & InspectAction.EmptyBytes) == 0:
        if bytes_len_after != bytes_len_before:
            sys.stderr.write("[get_msg_flow] bytes length mismatch: "
                             "%s -> %s\n" %
                             (bytes_len_before, bytes_len_after))

        if str(orig_hash.digest()).encode("HEX") \
           != str(mod_hash.digest()).encode("HEX"):
            sys.stderr.write("[get_msg_flow] bytes csum mismatch\n")

    else:
        sys.stderr.write("[get_msg_flow] there empty bytes\n")

    for fdir in msg_flow_acc.keys():
        stats = msg_flow_acc[fdir].stats
        # print per dir stats
        print "[get_msg_flow] ", fdir, bytes_len_before, stats
        # print session_info[fdir].cache
    print

    stream_errors &= ~(InspectAction.MaxNonCritical << 1 - 1)

    return msg_flow, stream_errors, st_time, end_time
