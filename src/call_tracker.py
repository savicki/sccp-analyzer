
import os, sys, argparse
from scapy.all import *
from scapy.contrib.skinny import *

from common_types import *
from call_info import *
from phone_session import PhoneSession, PhoneSessionIterator
from mtp_session import MTPSession, MTPSessionIterator, RelayPoint
from json_serialization import SkinnySessionsJsonEncoder, SkinnySessionsJsonDecoder

from filter import parse_expression


# list of sessions
sccp_sessions_map = {
    SkinnySessionFlags.Phone : [],
    SkinnySessionFlags.MTP : []
}

# call_id => CallInfo
callid_map = { }

# (rtp_local_ep, rtp_remote_ep) => [RtpFlow]
rtp_flows_duplex = { }
rtp_flows_partial = { }



def get_sibling_flows(flow, owner):
    return [s for s in owner.rtp_flows.values() if s != flow] if owner else []


"""
    Phone session         MTP session             MTP session             Phone session
         |                      |                       |                       |
     CallInfo               RelayPoint              RelayPoint               CallInfo
             \-- RTP flow --/        \-- RTP flow --/        \-- RTP flow --/
"""
def walk_flows(rtp_flows):
    for rtpf in rtp_flows:
        print rtpf
        
        reply_key = rtpf.get_inv_key()
        
        if rtp_flows_duplex.has_key(reply_key):
            reply_rtpf = rtp_flows_duplex[reply_key][0] # TODO: choose by time, not just first

            print reply_rtpf

            # JoinPair (MTP session) or CallInfo (Phone session)
            owner = reply_rtpf.get_owner()
            next_hop_flows = get_sibling_flows(reply_rtpf, owner)

            if len(next_hop_flows) == 0: 
                if isinstance(owner, CallInfo):
                    print '\t\\'
                    owner.dump_media_endpoint('Final endpoint:')
                    print '\nTrace completed'

                elif isinstance(owner, RelayPoint):
                    owner.dump_media_endpoint('RelayPoint')
                    print 'Trace lost..'
            else:
                owner.dump_media_endpoint('RelayPoint')

            walk_flows(next_hop_flows)

        else:
            print 'Trace lost - no end found for RTP flow above'
            print '\nTrace completed'

def trace_call(callid):
    print '\nTracing call [%s]...' % callid

    if callid_map.has_key(callid):
        found = False
        
        for call in callid_map[callid]:
            # only one call in set of calls with given Call-ID may have 'Connected' property
            if SkinnyCallStates.Connected in call.states_history.values():
                found = True
                break

        if found:
            call.dump_media_endpoint('\nStart endpoint:')
            print '\t/'

            walk_flows(call.rtp_flows.values())



parser = argparse.ArgumentParser()
parser.add_argument('-f', '--json-file', help='filename  to read and parse json from', required=True)
parser.add_argument('-m', '--mode', help='mode', required=True)
# mode 'search'
parser.add_argument('-s-filt', '--session-filter', help='session filter', default='')
parser.add_argument('-c-filt', '--call-filter', help='call filter', default='')
parser.add_argument('-s-calls', '--show-calls', help='whether to show calls WHEN call filter not specified', required=False, type=str, default='yes')
# mode 'trace'
parser.add_argument('-tc', '--trace-call', help='call id to trace', required=False, type=int, default=0)

# 
# Valid samples:
# 'session.session_errors & ErrorType2.UnknownSoftKey'
# 
if __name__ == "__main__":
    
    args = parser.parse_args()

    if args.mode != 'search' and args.mode != 'trace':
        raise ValueError('wrong mode \'%s\'' % args.mode)

    if args.mode == 'trace':
        if args.trace_call == None:
            raise ValueError('specify call id to trace')
    
    elif args.mode == 'search':
        show_calls_bydef = args.show_calls.lower() == 'yes'
        if args.session_filter.strip() == '' : args.session_filter = None
        if args.call_filter.strip() == '' : args.call_filter = None


    ### print args

    # print args # V-1

    with open(args.json_file, 'r') as json_file:
        json_str = json_file.read()

    sccp_sessions = json.loads(json_str, cls=SkinnySessionsJsonDecoder)
    # index stats
    stat_index_phone_sessions, stat_index_tot_calls, stat_index_rtp_flows_duplex, stat_index_rtp_flows_tot = 0, 0, 0, 0
    # search stats
    stat_srch_phone_sessions, stat_srch_tot_calls = 0, 0


    for session in sccp_sessions:

        #
        # search across flows and calls
        #

        if isinstance(session, PhoneSession):
            session_cls = SkinnySessionFlags.Phone
            stat_index_phone_sessions += 1
            
            if args.mode == 'search':
                eval_session_res = eval(parse_expression(args.session_filter, 'session')) if args.session_filter else True

                if eval_session_res:
                    stat_srch_phone_sessions += 1
                    session.show_session_details()

                    if args.call_filter or show_calls_bydef:
                        for call in session.calls.values():
                            eval_call_res = eval(parse_expression(args.call_filter, 'call')) if args.call_filter else show_calls_bydef

                            if eval_call_res:
                                stat_srch_tot_calls += 1
                                call.show_call_details()

        elif isinstance(session, MTPSession):
            session_cls = SkinnySessionFlags.MTP

        else:
            continue

        if args.mode != 'trace':
            continue

        #
        # index flows
        #


        # (1) split sessions by their type
        sccp_sessions_map[session_cls].append(session)

        # (2) index calls by their callid
        if session_cls == SkinnySessionFlags.Phone:
            for callid, call in session.calls.items():
                if not callid_map.has_key(callid):
                    callid_map[callid] = [call]
                else:
                    callid_map[callid].append(call) # only one call in callid range has Connected state
                stat_index_tot_calls += 1

        # (3) index rtp flows by their ip-port endpoints
        rtp_flows = session.get_rtp_flows()

        if len(rtp_flows) > 0:
            for rtpf in rtp_flows:
                #print rtpf, " FULL " if rtpf.is_two_way() else " PART "
                stat_index_rtp_flows_tot += 1
                if rtpf.is_two_way():
                    stat_index_rtp_flows_duplex += 1
                    flow_key = rtpf.get_key()
                    #print flow_key
                    if not rtp_flows_duplex.has_key(flow_key):
                        rtp_flows_duplex[flow_key] = [rtpf]
                    else:
                        #raise ValueError("FUCK")
                        ### print 'duplicate flow key: %s' % flow_key
                        rtp_flows_duplex[flow_key].append(flow_key)

                elif rtpf.is_one_way():
                    # TODO:
                    pass #print "one way", rtpf

    print

    if args.mode == 'search':
        print 'Search summary: phone sessions: %s, total calls: %s' % (
            stat_srch_phone_sessions, stat_srch_tot_calls)

    elif args.mode == 'trace':
        print 'Index summary: phone sessions: %s, total calls: %s, rtp flows: %s (total: %s)' % (
            stat_index_phone_sessions, stat_index_tot_calls, stat_index_rtp_flows_duplex, stat_index_rtp_flows_tot)

        trace_call( str(args.trace_call) )