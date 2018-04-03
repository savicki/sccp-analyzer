
#
# search sessions
#

python call_tracker.py -f calls_db.json -m 'search' -q 'session.owner.names has "Savi"'  -s-calls 'yes'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.owner.names has  "Savicki", "Paul"'  -s-calls 'no'

# but this return false positives
python call_tracker.py -f calls_db.json -m 'search' -q 'session.owner.numbers.len > 0' -s-calls 'yes'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.owner.numbers has "5120"' -s-calls 'no'

python call_tracker.py -f calls_db.json -m 'search' -q 'session.owner.protocol.used == 18' -s-calls 'no'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.owner.protocol.used == 0x12' -s-calls 'no'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.owner.protocol.used > 0x10' -s-calls 'no'


python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.session_flags has SkinnySessionFlags2.RealIpKnown'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.owner.ip == 10.0.101.235'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.owner.real_ip == 10.0.101.235'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.owner.real_ip == session.owner.ip'

python call_tracker.py -f calls_db.json -m 'search' -q 'session.owner.mac == "62:63:65:65:37:62"'


#
# search sessions by summaries
#

python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.call_errors.len > 0'  -s-calls 'no'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.call_errors.len == 0'  -s-calls 'no'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.call_errors has ErrorType2.UnknownSoftKey'  -s-calls 'no'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.call_errors has 1,2,3'  -s-calls 'no'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.call_errors has 1+2+4'  -s-calls 'no'

python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.call_states has SkinnyCallStates.Connected' -s-calls 'yes'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.call_states has SkinnyCallStates.Connected + SkinnyCallStates.RingIn'  -s-calls 'yes'

python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.call_attrs has SkinnyCallAttrs.P2P' -s-calls 'no'

python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.call_types has SkinnyCallType.INBOUND_CALL' -s-calls 'yes'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.call_types.len > 0' -s-calls 'yes'

python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.soft_keys has SkinnyKeyEvents.EndCall' -s-calls 'yes'

python call_tracker.py -f calls_db.json -m 'search' -q 'session.info.filename == "xxx.pcap"' -s-calls 'no'

python call_tracker.py -f calls_db.json -m 'search' -q 'session.info.filename contains "10.0.101.204_54336_10.0.3.3_2000_1505200105.pcap"' -s-calls 'no'
python call_tracker.py -f calls_db.json -m 'search' -q 'session.info.filename contains "10.0.2.192_"' -s-calls 'no'

python call_tracker.py -f calls_db.json -m 'search' -q 'session.summary.session_flags has SkinnySessionFlags2.FromBegining'

python call_tracker.py -f calls_db.json -m 'search' -q 'session.info.time.delta.end > 28' -s-calls 'no' 


#
# search calls
#

python call_tracker.py -f calls_db.json -m 'search' -q 'call.states has SkinnyCallStates.Connected' -s-calls 'yes'

python call_tracker.py -f calls_db.json -m 'search' -q 'call.rtp.flows.len == 1' 
python call_tracker.py -f calls_db.json -m 'search' -q 'call.rtp.flows.len > 1' 

python call_tracker.py -f calls_db.json -m 'search' -q '(call.rtp.flows.len > 0) && (call.id == 22652546)'

python call_tracker.py -f calls_db.json -m 'search' -q 'call.rtp.flows_duplex.len > 1'
python call_tracker.py -f calls_db.json -m 'search' -q 'call.rtp.flows_oneway.len > 1'

python call_tracker.py -f calls_db.json -m 'search' -q '(call.rtp.flows_duplex.len > 1) && ((call.soft_keys has SkinnyKeyEvents.Transfer) == False)'

python call_tracker.py -f calls_db.json -m 'search' -q 'call.rtp.stats.len > 0'
python call_tracker.py -f calls_db.json -m 'search' -q 'call.attrs has SkinnyCallAttrs.NoRtpStats'

python call_tracker.py -f calls_db.json -m 'search' -q '(call.errors has ErrorType2.RtpOneWayMediaNoRecv) && ((call.soft_keys has SkinnyKeyEvents.Transfer) == False)' --show-calls 'yes'

python call_tracker.py -f calls_db.json -m 'search' -q '(call.rtp.dur_min > 10) && (call.rtp.dur_max < 120)'

python call_tracker.py -f calls_db.json -m 'search' -q '(call.errors has ErrorType2.RtpOneWayMediaNoRecv) && ((call.soft_keys has SkinnyKeyEvents.Transfer) == False) && (call.rtp.stats.len == 1)'

python call_tracker.py -f calls_db.json -m 'search' -q '(call.errors has ErrorType2.RtpOneWayMediaNoRecv) && ((call.soft_keys has SkinnyKeyEvents.Transfer) == False) && (call.rtp.stats.len == 1) && (call.attrs has SkinnyCallAttrs.OneWayMediaSetup) == False && (call.rtp.dur_min > 2)'

python call_tracker.py -f calls_db.json -m 'search' -q 'call.id == 22672297' -s-calls 'no'

python call_tracker.py -f calls_db.json -m 'search' -q '(call.time.duration > 30) && (call.type == SkinnyCallType.INBOUND_CALL)'

python call_tracker.py -f calls_db.json -m 'search' -q 'call.callee.name contains "Savicki"' 
python call_tracker.py -f calls_db.json -m 'search' -q 'call.caller.name contains "Savicki"'

python call_tracker.py -f calls_db.json -m 'search' -q 'call.errors has ErrorType2.SoftKeyRepeat'

python call_tracker.py -f calls_db.json -m 's' -q 'call.errors has ErrorType2.RtpLostRecv, ErrorType2.RtpLostSend'

python call_tracker.py -f calls_db.json -m 's' -q 'call.attrs has SkinnyCallAttrs.LastCall'


#
# sessions + calls
#

python call_tracker.py -f calls_db.json -m 'search' -q '(session.owner.numbers.len > 1) && (call.states has SkinnyCallStates.Busy)' -s-calls 'no'

python call_tracker.py -f calls_db.json -m 'search' -q '(session.summary.call_errors.len > 0) && (call.errors.len > 0)'
python call_tracker.py -f calls_db.json -m 'search' -q '(session.summary.call_errors.len > 0) && (call.attrs has SkinnyCallAttrs.OneWayMediaSetup)'
python call_tracker.py -f calls_db.json -m 'search' -q '(session.summary.call_errors.len > 0) && ((call.attrs has SkinnyCallAttrs.OneWayMediaSetup) == False)'
python call_tracker.py -f calls_db.json -m 'search' -q '(session.summary.call_errors.len > 0) && ((call.attrs has SkinnyCallAttrs.OneWayMediaSetup) == True)'

python call_tracker.py -f calls_db.json -m 'search' -q '(session.summary.call_errors.len > 0) && (call.soft_keys has SkinnyKeyEvents.Transfer)'
python call_tracker.py -f calls_db.json -m 'search' -q '(session.summary.call_errors.len > 0) && (call.soft_keys has SkinnyKeyEvents.Transfer + SkinnyKeyEvents.Answer)'


#
# trace calls
#

python call_tracker.py -f calls_db.json -m 'trace' --trace-call '22728294'
python call_tracker.py -f calls_db.json -m 'trace' --trace-call '22728293'

#
# Index summary: phone sessions: 1003, total calls: 8536, rtp flows: 27441 (total: 39780)
#
# Tracing call [22728293]...
#
# Start endpoint:
#     [ 22728293 ] line: 1, call type: OutBoundCall
#     [  ]
#     [2017-09-12 12:30:02.676304 - 1970-01-01 03:00:00]
#     [Connected] #3282 (Savicki Oleg) --> #3864 (Pavlov Vladimir)
#     ['Off Hook', 'Proceeding', 'Ring out', 'Connected']
#     ['New Call']
#     /
# [28029059] ***.0.1.160:24626 --> 10.0.101.66:18306
# [28029055] 10.0.101.66:18306 --> ***.0.1.160:24626
#     \
#      RelayPoint [conf.: 31916111] [2017-09-12 12:30:16.825478]
#     /
# [28029056] 10.0.101.66:18328 --> 10.0.112.3:25556
# [28029057] 10.0.112.3:25556 --> 10.0.101.66:18328
#     \
#      RelayPoint [conf.: 31916112] [2017-09-12 12:30:16.825903]
#     /
# [28029058] 10.0.112.3:18852 --> **.0.6.214:24584
# [28029060] **.0.6.214:24584 --> 10.0.112.3:18852
#     \
# Final endpoint:
#     [ 22728294 ] line: 1, call type: InBoundCall
#     [ Established P2P ]
#     [2017-09-12 12:30:02.916832 - 2017-09-12 12:43:47.273683]
#     [Connected] #3282 (Savicki Oleg) --> #3864 (Pavlov Vladimir)
#     ['Ring in', 'Off Hook', 'Connected', 'On Hook']
#     ['Answer']
#
# Trace completed
#



#
# lost trace
#

python call_tracker.py -f calls_db.json -m 'trace' --trace-call '22744714'

#
# Index summary: phone sessions: 1003, total calls: 8536, rtp flows: 27441 (total: 39780)
#
# Tracing call [22744714]...
#
# Start endpoint:
# 	[ 22744714 ] line: 1, call type: InBoundCall
# 	[ Established P2P ]
# 	[2017-09-12 14:28:53.152292 - 2017-09-12 14:29:22.209727]
# 	[Connected] #3282 (Savicki Oleg) --> #5313 (Gomenuk Sergey)
# 	['Ring in', 'Off Hook', 'Connected', 'On Hook']
# 	['Answer']
# RTP stats:
# 	{u'packetsRecv': 2891, u'octetsSent': 461920, u'packetsSent': 2887, u'octetsRecv': 462560, u'packetsLost': 0}
# 	/
# [28040024] ***.0.3.136:24634 --> 10.0.3.2:18202
# Trace lost - no end found for RTP flow above
#
# Trace completed
#


#
# pcap parser
#

python pcap_parser.py -d 'c:\\github\\sccp-analyzer\\src\\pcaps\\13_sep_2017\\' -jf calls_db.json -pl 10 >calls_db.log 
python pcap_parser.py -d 'c:\\github\\sccp-analyzer\\src\\pcaps\\13_sep_2017\\' -f '10.0.101.235_58095_10.0.3.3_2000_1505125701.pcap' -jf calls_db.json >calls_db.log
python pcap_parser.py -d 'c:\\github\\sccp-analyzer\\src\\pcaps\\13_sep_2017\\' -ps '10.0.109.10_51139_10.0.3.3_2000_1505125721.pcap' -pl 1 -jf calls_db.json >calls_db.log

python pcap_parser.py -d 'c:\\github\\sccp-analyzer\\src\\pcaps\\13_sep_2017\\' -f '10.0.107.215_49841_10.0.3.3_2000_1505133586.pcap'


#
# endpoints
#

python call_tracker.py -f calls_db.json -m 'search' -q 'endpoint.sessions.len == 1'
python call_tracker.py -f calls_db.json -m 'search' -q 'endpoint.sessions.len > 1'
python call_tracker.py -f calls_db.json -m 'search' -q '(endpoint.sessions.len > 1) && (endpoint.channels.len == 1)'
python call_tracker.py -f calls_db.json -m 'search' -q '(endpoint.sessions.len > 1) && (endpoint.owner.names has "Mura")'

python call_tracker.py -f calls_db.json -m 'search' -q '(endpoint.sessions.len > 1) && (endpoint.channels.len > 2)'

python call_tracker.py -f calls_db.json -m 'search' -q '(endpoint.sessions.len > 1) && (endpoint.channels.len == 1) && (endpoint.falls.items.len > 1)'  

python call_tracker.py -f calls_db.json -m 'search' -q '(endpoint.owner.names has "Mura") && (endpoint.falls.intervals.min > 20)' -s-calls 'no'

python call_tracker.py -f calls_db.json -m 'search' -q '(endpoint.sessions.len > 1) && (endpoint.channels.len == 1) && ((endpoint.owner.names has "Klyuchevskaya") == False)' 


python call_tracker.py -f calls_db.json -m 'search' -q '(endpoint.owner.names has Murav) && (fall.duration < 30)'
python call_tracker.py -f calls_db.json -m 'search' -q '(endpoint.owner.names has Murav) && (fall.duration < 30) && (fall.last_call.duration > 100)' 

python call_tracker.py -f calls_db.json -m 'search' -q '(fall.last_call.duration > 100) && (fall.last_call.ends > 500) && (endpoint.owner.names has Murav) && (fall.duration < 30) && (fall.next_call.duration > 40) && (fall.next_call.starts < 10)' 

# find session restarting
python call_tracker.py -f calls_db.json -m 'search' -q '(fall.last_call.duration < 25) && (fall.last_call.ends < 20) && (fall.duration < 100) && (fall.next_call.duration > 20) && (fall.next_call.starts < 20)' 

python call_tracker.py -f calls_db.json -m 'search' -q '(fall.last_call.ends < 60) && (fall.duration < 200) && (fall.next_call.duration > 20) && (fall.next_call.starts < 60) && (fall.last_call.duration > 0) && (fall.next_call.duration > 0)' 
python call_tracker.py -f calls_db.json -m 'search' -q '(fall.last_call.ends < 120) && (fall.duration < 300) && (fall.next_call.duration > 20) && (fall.next_call.starts < 60) && (fall.last_call.duration > 0) && (fall.next_call.duration > 0)' 
python call_tracker.py -f calls_db.json -m 'search' -q '(fall.last_call.ends < 20) && (fall.duration < 300) && (fall.last_call.duration > 0) && (fall.next_call.duration > 0)' 

python call_tracker.py -f calls_db.json -m 'search' -q '(fall.last_call.visavi.number == "5342")'  
python call_tracker.py -f calls_db.json -m 'search' -q '(fall.last_call.visavi.number == fall.next_call.visavi.number)' 

python call_tracker.py -f calls_db.json -m 'search' -q '(fall.last_call.visavi.number == fall.next_call.visavi.number) && (fall.last_call.duration > 0)' 


#
# trouble capture scenarios; can be used for daily trouble lookups
# 

# soft key repeated, followed by phone restart
# reliability: high
python call_tracker.py  -f calls_db/calls_db__XXX_dec.json -m 'search' -q '(call.errors has ErrorType2.SoftKeyRepeat) && (call.attrs has SkinnyCallAttrs.LastCall)'

# phone restart
# reliability: high
python call_tracker.py  -f calls_db/calls_db__XXX_dec.json -m 'search' -q 'fall.duration < 60'

# fall with re-call
# reliability: high
python call_tracker.py -f calls_db/calls_db__XXX_dec.json -m 'search' -q '(fall.last_call.visavi.number == fall.next_call.visavi.number) && (fall.last_call.duration > 0)' 

# too many channels 
# reliability: high
python call_tracker.py  -f calls_db/calls_db__XXX_dec.json -m 'search' -q  'endpoint.channels.len > 2'

# lost RTP during conversation
# reliability: high
python call_tracker.py  -f calls_db/calls_db__XXX_dec.json -m 'search' -q  '(call.errors has ErrorType2.RtpLostRecv) && ((call.errors has ErrorType2.RtpLostSend) == False)'

# too short and last-in-session call
# reliability: low
python call_tracker.py  -f calls_db/calls_db__XXX_dec.json -m 'search' -q  '(call.time.duration < 23) && (call.time.duration > 10) && (call.states has SkinnyCallStates.Connected) && (call.attrs has SkinnyCallAttrs.LastCall)'

# zero stats
# reliability: high
python call_tracker.py  -f calls_db/calls_db__XXX_dec.json -m 'search' -q  '(call.errors has ErrorType2.RtpOneWayMediaNoRecv) && ((call.errors has ErrorType2.RtpOneWayMediaNoSend) == False) && (call.time.duration > 10)'



# signal sessions overlapping
python call_tracker.py  -f calls_db/calls_db__XXX_dec.json -m 'search' -q 'fall.duration < 0'