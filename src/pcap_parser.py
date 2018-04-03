
import os, sys, argparse, time
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


def process_pcap(filepath, filename):
    print "[process_pcap] [ %s ] (start) [ %s ]" % (datetime.datetime.now().strftime("%H:%M:%S.%f"), filename)

    pcap = rdpcap(filepath)

    print "[process_pcap] [ %s ] rdpcap() completed" % datetime.datetime.now().strftime("%H:%M:%S.%f")

    pcap_sessions = pcap.sessions(hash_session)

    pcap_sccp_sessions = []

    print "[process_pcap] [ %s session(s) ]" % len(pcap_sessions)

    for pcap_session_key in pcap_sessions:
        print "[process_pcap] ", pcap_session_key

        msg_session, stream_errors, pkt_st_time, pkt_end_time = get_msg_flow(pcap_sessions[pcap_session_key])


        classify_iter = SessionClassifier()
        try:
            session_flags = iterate_session( msg_session, classify_iter, 
                # session context
                (
                    SessionClassifyContext(), 
                    create_session_classifier()
                ) )
        except:
            print "[process_pcap] got exception in iterate_session( SessionClassifier ) for [ %s ]" % filename 
            continue

        print "[process_pcap] session_flags: (%s) '%s'" % (hex(session_flags), SkinnySessionFlags.str(session_flags))
        
        if session_flags & SkinnySessionFlags.Phone:
            inspect_iter = PhoneSessionIterator()
            sccp_session = PhoneSession()

        elif session_flags & SkinnySessionFlags.MTP:
            inspect_iter = MTPSessionIterator()
            sccp_session = MTPSession()

        else:
            inspect_iter = None
        
        if inspect_iter:
            sccp_session.s_info.filename = filename

            m = re.match(r'^TCP (?P<local_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<local_port>\d{1,5}) -- (?P<remote_ip>\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(?P<remote_port>\d{1,5})', 
                pcap_session_key)
            if not m:
                raise ValueError('cannot parse IP info from filename')

            if int(m.group('remote_port')) == SCCP_PORT:
                ip_info = IpInfo(
                        local_ip = m.group('local_ip'),
                        local_port = m.group('local_port'),
                        remote_ip = m.group('remote_ip'),
                        remote_port = m.group('remote_port'),
                        st_time = pkt_st_time,
                        end_time = pkt_end_time
                    )
            else:
                raise ValueError('remote port not 2000')

            sccp_session.ip_info = ip_info
            try:
                sccp_errors = iterate_session(msg_session, inspect_iter, sccp_session)
            except:
                print "[process_pcap] got exception in iterate_session( ***SessionIterator ) for [ %s ]" % filename 
                continue

            if sccp_errors != ErrorType2.No:
                sys.stderr.write( "**** session has errors: %s (%s)\n" % (
                    hex(sccp_errors), ErrorType2.str(sccp_errors)) )

            # if isinstance(sccp_session, PhoneSession) or isinstance(sccp_session, MTPSession):
            #   print sccp_session.to_json()
            pcap_sccp_sessions.append(sccp_session)

    print "[process_pcap] (end)"

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

        sccp_sessions_from_pcap = process_pcap( os.path.join(args.dir, filename), filename )
        
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