
from enum import *
import datetime, time, json
from common_types import SkinnySessionFlags, SessionBase, SessionIterator, SessionHandler, JsonSerializable, ErrorType2, MediaEndpoint
from call_info import *


# bind 2+ RTP flows together within MTP session
class RelayPoint(JsonSerializable, Ownable, MediaEndpoint):
    def __init__(self, conf_id = 0, session_owner = None, data = None):
        Ownable.__init__(self)

        if data:
            self.__dict__ = data

            for rtpf in self.rtp_flows.values():
                rtpf.set_owner(self)
        else:
            # ppid => RtpFlow
            self.rtp_flows = {}
            self.conf_id = conf_id
            self.__owner = session_owner

            self.st_time = 0


    def get_rtp_flow(self, ppid, create_if_not_exist = False):
        exist = self.rtp_flows.has_key(ppid)        

        if not exist and create_if_not_exist:
            self.rtp_flows[ppid] = RtpFlow(ppid)
            self.__owner.set_relay_point_by_ppid(ppid, self)            
            exist = not exist

        return self.rtp_flows[ppid] if exist else None


    def __str__(self):
        ### print self.conf_id
        ### print self.rtp_flows.keys()
        res_str = "[conf.: %s] [%s]" % (self.conf_id, datetime.datetime.fromtimestamp(self.st_time))
        if len(self.rtp_flows.values()) > 0:
            res_str += "\n"
            for rtp_flow in self.rtp_flows.values():
                res_str += "\t" + str(rtp_flow) + "\n"

        return res_str


    def dump_media_endpoint(self, label = ''):
        res_str = '\t %s [conf.: %s] [%s]' % (
            label, self.conf_id, datetime.datetime.fromtimestamp(self.st_time))
        print '\t\\'
        print res_str
        print '\t/'


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class MTPSession(SessionBase, JsonSerializable):
    def __init__(self, data = None):
        SessionBase.__init__(self)

        if data:
            self.__dict__ = data

            for rp in self.relay_points.values():
                rp.set_owner(self)

        else:
            self.relay_points = {}
            self.relay_points_confid_list = [] # history
            # access RP via child PPID, 
            # actually only during pcap-session reconstruction 
            self.__relay_points_by_ppid = {}


    def get_relay_point(self, conf_id, create_if_not_exist = False):
        exist = self.relay_points.has_key(conf_id)
        created = False

        if not exist and create_if_not_exist:
            new_rp = RelayPoint(conf_id, self)
            self.relay_points[conf_id] = new_rp
            self.relay_points_confid_list.append(new_rp.conf_id)

            exist = not exist
            created = True

        return (self.relay_points[conf_id] if exist else None, created)


    def get_relay_point_by_ppid(self, ppid):
        return self.__relay_points_by_ppid[ppid] if self.__relay_points_by_ppid.has_key(ppid) else None


    def set_relay_point_by_ppid(self, ppid, rp):
        if not self.__relay_points_by_ppid.has_key(ppid):
            self.__relay_points_by_ppid[ppid] = rp


    def iterate(self, fn):
        for conf_id in self.relay_points_confid_list:
            rp = self.relay_points[conf_id]
            fn(rp.conf_id, rp)


    def get_rtp_flows(self):
        flows_arr = [rp.rtp_flows.values() for rp in self.relay_points.values()]
        return reduce( lambda x, y : x + y, flows_arr ) if len(flows_arr) > 0 else []


    # def to_json(self):
    #     return json.dumps(get_public_fields(self.__dict__), cls=MTPSessionJsonEncoder, indent=4)


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class MTPSessionIterator(SessionIterator, SessionHandler):

    def __init__(self):
        SessionIterator.__init__(self)
        SessionHandler.__init__(self)

        SessionHandler._init_handlers(self, self.__class__.__name__)        


    def open_session(self, context):
        SessionIterator.open_session(self, context) 


    def close_session(self):
        
        def print_rp(conf_id, rp):
            print rp
        
        self._context.iterate(print_rp)

        return ErrorType2.No


    def process_msg(self, sccp_msg, fdir, pkt_time):        
        stop_processing = False
    #     # print "[PhoneSessionIterator::process_msg] msg: %s, len: %s + 12 bytes, ver.: %s, dir: %s, time: %s" % (
    #     #     hex(sccp_msg.msg), sccp_msg.len, sccp_msg.res, fdir, pkt_time)

    #     if self._context.is_bypass_mode() == False:
        if self._handlers.has_key(sccp_msg.msg):
            func = self._handlers[sccp_msg.msg]

            #print 'process msg: %s (%s), dir: %s' % (skinny_messages_cls[sccp_msg.msg], hex(sccp_msg.msg), fdir)
            #sccp_msg.show()
            stop_processing = func(sccp_msg, fdir, pkt_time)

        return stop_processing


    #
    # to CCM, Dir.DIR_ORIG
    #


    def __process__0x0022__open_receive_channel_ack(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageOpenReceiveChannelAck]
        #sub_msg.show()

        rp = self._context.get_relay_point_by_ppid(sub_msg.passthru)

        if rp:         
            rtp_flow = rp.get_rtp_flow(sub_msg.passthru)

            if rtp_flow:
                rtp_flow.flags |= RtpFlowFlags.LocalConfirmed
                rtp_flow.local = (sub_msg.remote, sub_msg.port)
                rtp_flow.set_st_timestamp(pkt_time)


    # def __process__0x0154__start_media_transmission_ack(self, msg, fdir, pkt_time):
        
    #     self._test_no_raw_layer(msg)

    #     sub_msg = msg[SkinnyMessageStartMediaTransmissionAck]
    #     #sub_msg.show()

    #     if self._context.calls.has_key(sub_msg.conference):             
    #         call_info = self._context.calls[sub_msg.conference]

    #         rtp_flow = call_info.get_rtp_flow(sub_msg.passthru)
    #         rtp_flow.flags |= RtpFlowFlags.RemoteConfirmed
    #         rtp_flow.local_orig = (sub_msg.remote, sub_msg.port)
    #         rtp_flow.set_st_timestamp(pkt_time)

    #
    # from CCM, Dir.DIR_REPLY
    #


    def __process__0x0105__open_receive_channel(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageOpenReceiveChannel]
        #sub_msg.show()

        rp, created = self._context.get_relay_point(sub_msg.conference, True)

        if created:
            rp.st_time = pkt_time

        if rp:
            rtp_flow = rp.get_rtp_flow(sub_msg.passthru, True)

            if rtp_flow:
                
                rtp_flow.flags |= RtpFlowFlags.Local
                rtp_flow.remote_orig = (sub_msg.remote, sub_msg.remotePortNumber)
                rtp_flow.set_st_timestamp(pkt_time)
                rtp_flow.local_rate = sub_msg.rate # recv rate


    def __process__0x008A__start_media_transmission(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageStartMediaTransmission]
        #sub_msg.show()

        rp = self._context.get_relay_point(sub_msg.conference, False)[0]

        if rp:
            rtp_flow = rp.get_rtp_flow(sub_msg.passthru)

            if rtp_flow:
                rtp_flow.flags |= RtpFlowFlags.Remote
                rtp_flow.remote = (sub_msg.remote, sub_msg.port)
                rtp_flow.set_st_timestamp(pkt_time)
                rtp_flow.remote_rate = sub_msg.rate # send rate


    def __process__0x0106__close_receive_channel(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageCloseReceiveChannel]
        #sub_msg.show()

        rp = self._context.get_relay_point(sub_msg.conference, False)[0]

        if rp:          
            rtp_flow = rp.get_rtp_flow(sub_msg.passthru)

            if rtp_flow:
                rtp_flow.flags |= RtpFlowFlags.LocalClosed
                rtp_flow.set_end_timestamp(pkt_time)


    def __process__0x008B__stop_media_transmission(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageStopMediaTransmission]
        #sub_msg.show()

        rp = self._context.get_relay_point(sub_msg.conference, False)[0]

        if rp:           
            rtp_flow = rp.get_rtp_flow(sub_msg.passthru)

            if rtp_flow:
                rtp_flow.flags |= RtpFlowFlags.RemoteClosed
                rtp_flow.set_end_timestamp(pkt_time)


    def __process__0x002A__media_transmission_failure(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageMediaTransmissionFailure]
        #sub_msg.show()

        rp = self._context.get_relay_point(sub_msg.conference, False)[0]

        if rp:           
            rtp_flow = rp.get_rtp_flow(sub_msg.passthru)

            if rtp_flow:
                rtp_flow.flags |= RtpFlowFlags.RemoteFailure
                rtp_flow.set_end_timestamp(pkt_time)


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #

