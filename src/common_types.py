
import re, json
from enum import *
from constants import *
from scapy.contrib.skinny import *


class BitEnum(IntEnum):
    # mandatory for BIT enums - to unify JSON representation 
    # of single- and non-single bits value 
    def __str__(self):
        return str(self.value)


class Dir(IntEnum):
    DIR_ORIG = 0 # to CCM
    DIR_REPLY = 1 # to phone
    DIR_MAX = 2

def get_dir(dport):
    return Dir.DIR_ORIG if dport == SCCP_PORT else Dir.DIR_REPLY


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 


# layer-1
class InspectAction(BitEnum):
    No              = 0
    Pass            = 1 << 0 # pkt contain at least 1 complete msg, leave as is
    InjectBefore    = 1 << 1 # inject pkt(s) before this packet
    MaxNonCritical  = InjectBefore

    EmptyBytes      = 1 << 2 # [suspict] sequence of zero bytes
    Error           = 1 << 3 # error recovering session


class PacketState(BitEnum):
    WithPriorInjects = 1
    Single          = 1 << 1
    PartialBegin    = 1 << 2 # not traced
    PartialEnd      = 1 << 3
    OneOfMultiple   = 1 << 4


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 


class SkinnySessionFlags2(BitEnum):
    No              = 0
    FromBegining    = 1 << 0
    RealIpKnown     = 1 << 1 # at least 1 OpenReceiveChannelAck msg was captured


# layer-2
class SkinnySessionFlags(BitEnum):
    No          = 0
    KeepAlive   = 1 << 0
    KeepAliveAck= 1 << 1
    Phone       = 1 << 2
    MTP         = 1 << 3

    @staticmethod
    def str(attrs):
        return reduce(
            lambda x, y : x + (" " if x != "" and y != "" else "") + y,
            map( (lambda attr: skinny_session_flags[attr] if (attr & attrs) == attr else ""), skinny_session_flags.keys() )
        )

skinny_session_flags = {
    SkinnySessionFlags.No : "",
    SkinnySessionFlags.KeepAlive    : "KeepAlive",
    SkinnySessionFlags.KeepAliveAck : "KeepAliveAck",
    SkinnySessionFlags.Phone        : "Phone",
    SkinnySessionFlags.MTP          : "MTP",
}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 


# layer-3
class ErrorType2(BitEnum):
    No                      = 0

    #
    # critical errors - can't continue session processing (turn on bypass mode)
    #
    NotSupportedProto       = 1 << 0 
    MaxCritical = NotSupportedProto

    #
    # non-critical errors
    #
    OutOfState              = 1 << 1 
    
    # connections stats with 0 packets received
    RtpOneWayMediaNoRecv    = 1 << 2
    # connections stats with 0 packets sent
    RtpOneWayMediaNoSend    = 1 << 3

    RtpNoMedia              = 1 << 4
    RtpMediaFailure         = 1 << 5

    SoftKeyOutOfState       = 1 << 6  # EndCall after call closed, multiple EndCalls (session hangup?)
    SoftKeyUnknown          = 1 << 7  # not bound to any call
    # sequence of same SoftKey - session hangup (lost link with UCM?)
    SoftKeyRepeat           = 1 << 8 

    # not getting KeepAlive/KeepAliveAck within specified interval (lost link with CCM)
    KeepAliveLost           = 1 << 9
    # lost RTP after non-zero RTP interval
    RtpLostSend             = 1 << 10
    RtpLostRecv             = 1 << 11


    @staticmethod
    def str(attrs):
        return reduce(
            lambda x, y : x + (" " if x != "" and y != "" else "") + y,
            map( (lambda attr: skinny_error_types[attr] if (attr & attrs) == attr else ""), skinny_error_types.keys() )
        )

skinny_error_types = {
    ErrorType2.No : "",
    ErrorType2.NotSupportedProto    : "NotSupportedProto",
    
    ErrorType2.OutOfState           : "OutOfState",

    ErrorType2.RtpOneWayMediaNoRecv : "RtpOneWayMediaNoRecv",
    ErrorType2.RtpOneWayMediaNoSend : "RtpOneWayMediaNoSend",
    ErrorType2.RtpNoMedia           : "RtpNoMedia",
    ErrorType2.RtpMediaFailure      : "RtpMediaFailure",
    
    ErrorType2.SoftKeyOutOfState    : "SoftKeyOutOfState",
    ErrorType2.SoftKeyUnknown       : "SoftKeyUnknown",
    ErrorType2.SoftKeyRepeat        : "SoftKeyRepeat",

    ErrorType2.KeepAliveLost        : "KeepAliveLost",

    ErrorType2.RtpLostSend          : "RtpLostSend",
    ErrorType2.RtpLostRecv          : "RtpLostRecv"
}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 


class SessionBase(object):
    def __init__(self):
        self.s_info = SessionInfo()


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 


class SessionIterator(object):

    def __init__(self):
        self._context = None

    def open_session(self, context):
        self._context = context

    def process_msg(self, sccp_msg, fdir, pkt_time):
        print "[SessionIterator::process_msg] msg: %s, len: %s + 12 bytes, ver.: %s" % (
            hex(sccp_msg.msg), sccp_msg.len, sccp_msg.res)
        return False

    def close_session(self):
        return None # return value is up to user specific


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 


class SessionHandler(object):
    
    def __init__(self):
        self._handlers = {}


    def _test_no_raw_layer(self, msg):
        if msg.haslayer(Raw):
            raise ValueError("msg '%s' (%s + 12 bytes) has RAW data" % (skinny_messages_cls[msg.msg], msg.len))


    def _init_handlers(self, child_class_name):
        #print self.__class__.__name__
        #print dir(self)
        #print self.__dict__

        PATTERN = r'_%s__process__(?P<id>0x[\d\w]{4})__' % child_class_name
        
        for member in dir(self):
            m = re.search(PATTERN, member)
            if m:
                self._handlers[int(m.group('id'), 0)] = getattr(self, member)


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class JsonSerializable(object):
    def get_json_dict(self):
        return JsonSerializable.get_public_fields(self.__dict__)

    @staticmethod
    def get_public_fields(dict_arg):
        return dict([(k, v) for k, v in dict_arg.iteritems() if k.startswith('_') == False ])


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # 


class SessionInfo(JsonSerializable):
    def __init__(self, data = None):

        if data:
            self.__dict__ = data

        else:
            self.filename = ''
            # first msg
            self.st_time = None
            # last msg
            # this msg timerange must not differ from tcp range in more than 'KeepAlive' interval
            self.end_time = None


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class IpInfo(JsonSerializable):
    def __init__(self, data = None, local_ip = None, local_port = None, remote_ip = None, remote_port = None, st_time = None, end_time = None):

        if data:
            self.__dict__ = data

        else:
            self.local_ip = local_ip
            self.local_port = local_port

            # CCM endpoint
            self.remote_ip = remote_ip
            self.remote_port = remote_port

            self.st_time = st_time
            self.end_time = end_time


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class RtpFlowsContainer(object):
    def get_rtp_flows(self):
        return None


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class Ownable(object):
    def __init__(self, who=''):
        self._owner = None
        #print who

    def get_owner(self):
        return self._owner

    def set_owner(self, owner):
        #if self._owner == None:
        self._owner = owner


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class MediaEndpoint(object):
    def dump_media_endpoint(self, label = ''):
        pass