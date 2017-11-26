
import os, sys, argparse
from scapy.all import *
from scapy.contrib.skinny import *

from common_types import *
from stream_layer import hash_session, get_msg_flow
from session_classifier import *
from call_info import *
from phone_session import PhoneSession, PhoneSessionIterator
from mtp_session import MTPSession, MTPSessionIterator, RelayPoint
from json_serialization import SkinnySessionsJsonEncoder, SkinnySessionsJsonDecoder


skip_names = [
]


def iterate_session(msg_flow, iterator, context = None):
    
    ### print "[iterate_session] prev_layer_status = %s" % hex(prev_layer_status)

    iterator.open_session(context)

    has_exception = False

    for pkt in msg_flow:

        tcp = pkt[TCP]
        sccp = tcp[Skinny]

        # try:
        if iterator.process_msg(sccp, get_dir(pkt.dport), pkt.time):
            print "[iterate_session] : stopped"
            break
        # except Exception as inst:
        #   has_exception = True
        #   sys.stderr.write( "[inspect_skinny_session] raised exception: '%s', exit" % inst )
        #   break
    
    user_data = iterator.close_session()

    return user_data


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


def process_pcap(filename):

    pcap = rdpcap(filename)

    pcap_sessions = pcap.sessions(hash_session)
    pcap_sccp_sessions = []

    print "[process_pcap] [ %s ] [ %s session(s) ]" % (filename, len(pcap_sessions))

    for pcap_session_key in pcap_sessions:
        print "[process_pcap] ", pcap_session_key

        msg_session, stream_errors = get_msg_flow( pcap_sessions[pcap_session_key] )


        classify_iter = SessionClassifier()
        session_flags = iterate_session( msg_session, classify_iter, 
            # session context
            (
                SessionClassifyContext(), 
                create_session_classifier()
            ) )

        print "session_flags: (%s) '%s'" % ( hex(session_flags), SkinnySessionFlags.str(session_flags) )
        
        if session_flags & SkinnySessionFlags.Phone:
            inspect_iter = PhoneSessionIterator()
            sccp_session = PhoneSession()

        elif session_flags & SkinnySessionFlags.MTP:
            inspect_iter = MTPSessionIterator()
            sccp_session = MTPSession()

        else:
            inspect_iter = None
        
        if inspect_iter:
            sccp_errors = iterate_session( msg_session, inspect_iter, sccp_session )
            # TODO: 
            # print sccp_errors
            if sccp_errors != ErrorType2.No:
                sys.stderr.write( "**** session has errors: %s (%s)\n" % (
                    hex(sccp_errors), ErrorType2.str(sccp_errors)) )

            # if isinstance(sccp_session, PhoneSession) or isinstance(sccp_session, MTPSession):
            #   print sccp_session.to_json()
            pcap_sccp_sessions.append(sccp_session)

    return pcap_sccp_sessions

# # TODO:
# class TcpSession:
#   sccp_sessions = []
#   tcp_errors = No
#   sccp_flow = No # Mtp/Phone
sccp_sessions = [] # TcpSession, then SessionBase instance (Phone, Mtp)

parser = argparse.ArgumentParser()

parser.add_argument('-d', '--dir', help='directory with pcap files', required=True)
parser.add_argument('-f', '--pcap-file', help='particular .pcap filename', required=False)

parser.add_argument('-ps', '--pcap-start', help='.pcap filename to start from', required=False)
parser.add_argument('-pl', '--pcap-limit', help='.pcap limit', required=False, type=int, default=0)

parser.add_argument('-jf', '--json-file', help='filename to save json output', required=False)


if __name__ == "__main__":

    args = parser.parse_args()
    ### print args
    filenames = [args.pcap_file] if args.pcap_file  else os.listdir(args.dir)
    start_filename = args.pcap_start
    pcap_limit = args.pcap_limit

    
    #print files
    start_read = len(filenames) == 1
    processed_pcaps = 0


    for filename in filenames:      

        if start_read == False and start_filename:
            start_read = (filename == start_filename)

            if start_read == False:
                continue

        if filename in skip_names and len(filenames) > 1:
            print "skip %s" % filename
            continue

        fullpath = os.path.join(args.dir, filename)
        sccp_sessions_from_pcap = process_pcap(fullpath)
        
        if len(sccp_sessions_from_pcap) > 0:
            sccp_sessions += sccp_sessions_from_pcap

        processed_pcaps += 1
        if pcap_limit > 0 and processed_pcaps == pcap_limit:
            print 'pcap limit %s reached, exit' % pcap_limit
            break

    if args.json_file:
        calls_json = json.dumps(sccp_sessions, cls=SkinnySessionsJsonEncoder, indent=4)

        json_file = open(args.json_file, "w") 
        json_file.write(calls_json) 
        json_file.close()