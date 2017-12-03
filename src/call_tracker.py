
import os, sys, argparse
from scapy.all import *
from scapy.contrib.skinny import *

from common_types import *
from call_info import *
from phone_session import PhoneSession, PhoneSessionIterator
from mtp_session import MTPSession, MTPSessionIterator, RelayPoint
from endpoint_info import EndpointInfo
from json_serialization import SkinnySessionsJsonEncoder, SkinnySessionsJsonDecoder

from filter import parse_expression, stringify_filter_map


# list of sessions
_sessions_map = {
    SkinnySessionFlags.Phone : [],
    SkinnySessionFlags.MTP : []
}

# call_id => CallInfo
_call_map = { }

# (rtp_local_ep, rtp_remote_ep) => [RtpFlow]
_rtp_flows_duplex_map = { }
_rtp_flows_partial_map = { }

# owner => [session], sorted by time
_endpoint_map = { }


def _get_sibling_flows(flow, owner):
    return [s for s in owner.rtp_flows.values() if s != flow] if owner else []


"""
    Phone session         MTP session             MTP session             Phone session
         ^                      ^                       ^                       ^
         |                      |                       |                       |
     CallInfo               RelayPoint              RelayPoint               CallInfo
             \-- RTP flow --/        \-- RTP flow --/        \-- RTP flow --/
"""
def _walk_flows(rtp_flows):
    for rtpf in rtp_flows:
        if rtpf.is_two_way() == False:
            continue
        print rtpf
        
        reply_key = rtpf.get_inv_key()
        
        if _rtp_flows_duplex_map.has_key(reply_key):
            reply_rtpf = _rtp_flows_duplex_map[reply_key][0] # TODO: choose by time, not just first

            print reply_rtpf

            # JoinPair (MTP session) or CallInfo (Phone session)
            owner = reply_rtpf.get_owner()
            next_hop_flows = _get_sibling_flows(reply_rtpf, owner)

            if len(next_hop_flows) == 0: 
                if isinstance(owner, CallInfo):
                    print '\t\\'
                    owner.dump_media_endpoint('Final endpoint:')
                    print '\nTrace completed\n'

                elif isinstance(owner, RelayPoint):
                    owner.dump_media_endpoint('RelayPoint')
                    print 'Trace lost..'
            else:
                owner.dump_media_endpoint('RelayPoint')

            _walk_flows(next_hop_flows)

        else:
            print 'Trace lost - no end found for RTP flow above'
            print '\nTrace completed\n'


def _trace_call(callid):
    print '\nTracing call [%s]...' % callid

    if _call_map.has_key(callid):
        found = False
        
        for call in _call_map[callid]:
            # only one call in set of calls with given Call-ID may have 'Connected' property
            if SkinnyCallStates.Connected in call.states_history.values():
                found = True
                break

        if found:
            call.dump_media_endpoint('\nStart endpoint:')
            print '\t/'

            _walk_flows(call.rtp_flows.values())


def _build_expression(from_str, scope, strict_scope = False):
    expr = None
    dummy = True

    if from_str.strip() != '':
        expr, dummy = parse_expression(from_str, scope, strict_scope = strict_scope)

    return expr if not dummy else None


parser = argparse.ArgumentParser(
    description='Convert sccp .pcaps (captured with "tcp.port eq 2000" filter) to json calls database, index these calls, search and trace by call-id, dump sessions',
    formatter_class=argparse.RawTextHelpFormatter,
    epilog='Filter tree:\n%s' % stringify_filter_map())

parser.add_argument('-f', '--file', help='filename  to read and parse json from', required=True)
parser.add_argument('-m', '--mode', help='mode', required=True)
# 'search' mode
parser.add_argument('-q', '--query', help='query', default='')
parser.add_argument('-s-calls', '--show-calls', help='whether to show calls when call-level filter not specified', required=False, type=str, default='yes')
# 'trace' mode
parser.add_argument('-t', '--trace-call', help='call id to trace', required=False, type=int, default=0)

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
        session_expr = _build_expression(args.query, 'session')
        call_expr   = _build_expression(args.query, 'call')
        endpoint_expr  = _build_expression(args.query, 'endpoint')

    ### print args

    # print args # V-1

    with open(args.file, 'r') as file:
        json_str = file.read()

    sccp_sessions = json.loads(json_str, cls=SkinnySessionsJsonDecoder)
    # index stats
    stat_index_phone_sessions, stat_index_tot_calls, stat_index_rtp_flows_duplex, stat_index_rtp_flows_tot = 0, 0, 0, 0
    # search stats
    stat_srch_phone_sessions, stat_srch_calls, stat_srch_endpoints = 0, 0, 0


    for session in sccp_sessions:

        #
        # search across flows and calls
        #

        if isinstance(session, PhoneSession):

            session_cls = SkinnySessionFlags.Phone
            stat_index_phone_sessions += 1
            
            #
            # perform search over raw (not indexed) data
            #
            if args.mode == 'search':
                eval_session_res = eval(session_expr) if session_expr else endpoint_expr == None

                if eval_session_res:
                    session_shown = False

                    # go deep
                    if len(session.calls) > 0 and (call_expr or show_calls_bydef):
                        for call in session.calls.values():
                            eval_call_res = eval(call_expr) if call_expr else show_calls_bydef

                            if eval_call_res:
                                if not session_shown:
                                    stat_srch_phone_sessions += 1
                                    session.show_session_details()
                                    session_shown = True

                                stat_srch_calls += 1
                                call.show_call_details()

                    else:
                        stat_srch_phone_sessions += 1
                        session.show_session_details()
                        session_shown = True
                   
        elif isinstance(session, MTPSession):
            session_cls = SkinnySessionFlags.MTP

        else:
            continue

        if args.mode != 'trace' and endpoint_expr == None:
            continue

        #
        # index flows
        #


        # (1) split sessions by their type
        _sessions_map[session_cls].append(session)

        # (2) index calls by their callid
        if session_cls == SkinnySessionFlags.Phone:
            for callid, call in session.calls.items():
                if not _call_map.has_key(callid):
                    _call_map[callid] = [call]
                else:
                    _call_map[callid].append(call) # only one call in callid range has Connected state
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
                    if not _rtp_flows_duplex_map.has_key(flow_key):
                        _rtp_flows_duplex_map[flow_key] = [rtpf]
                    else:
                        #raise ValueError("FUCK")
                        ### print 'duplicate flow key: %s' % flow_key
                        _rtp_flows_duplex_map[flow_key].append(flow_key)

                elif rtpf.is_one_way():
                    # TODO:
                    pass #print "one way", rtpf

        # (4) group phone sessions by owner
        if session_cls == SkinnySessionFlags.Phone:
            for line in session.register_info['name'].keys():
                # TODO: session should has one owner name
                owner_name = session.register_info['name'][line]

                if not _endpoint_map.has_key(owner_name):
                    _endpoint_map[owner_name] = EndpointInfo( session.register_info )

                endpoint = _endpoint_map[owner_name]
                ind = 0
                for e_session in endpoint.sessions:
                    if e_session.s_info.st_time > session.s_info.end_time:
                        break
                    i += 1

                endpoint.sessions.insert(ind, session)
    #
    # END 'for session in sccp_sessions:'
    #

    # (5) post-process endpoints
    for endpoint in _endpoint_map.values():
        pass


    #
    # perform search over indexed data
    #

    if endpoint_expr:
        for endpoint in _endpoint_map.values():
            eval_endpoint_res = eval(endpoint_expr)
            if eval_endpoint_res:
                stat_srch_endpoints += 1
                print endpoint.owner["name"].values()


    if args.mode == 'search':
        print '\nSearch summary: phone sessions: %s, calls: %s, endpoints: %s' % (
            stat_srch_phone_sessions, stat_srch_calls, stat_srch_endpoints)

    elif args.mode == 'trace':
        print '\nIndex summary: phone sessions: %s, total calls: %s, rtp flows: %s (total: %s)' % (
            stat_index_phone_sessions, stat_index_tot_calls, stat_index_rtp_flows_duplex, stat_index_rtp_flows_tot)

        _trace_call( str(args.trace_call) )