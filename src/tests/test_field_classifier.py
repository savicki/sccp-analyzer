from scapy.all import *
from scapy.contrib.skinny import *

from common_types import *
from call_info import *
from session_info import *
from field_classifier import *
from session_classifier import *


call_type_classifier = FieldClassifier({

            SkinnyCallAttrs.Established : [( DictValuesField("states_history"), 
                                            [
                                                SkinnyCallStates.Connected
                                            ], True )],

            SkinnyCallAttrs.ExternalNum : [], # TODO

            SkinnyCallAttrs.Interrupted : [( DictValuesField("states_history"), 
                                            [
                                                SkinnyCallStates.Hold
                                            ], True )],

            SkinnyCallAttrs.P2P         : [( DictValuesField("keys_history"), 
                                            [
                                                SkinnyKeyEvents.Transfer, 
                                                SkinnyKeyEvents.Confrn, 
                                                SkinnyKeyEvents.Join
                                            ], False )],

            SkinnyCallAttrs.Forward     : [], # TODO

            SkinnyCallAttrs.Transfer    : [
                                            ( DictValuesField("keys_history"),  
                                            [
                                                SkinnyKeyEvents.Transfer, 
                                                SkinnyKeyEvents.Resume
                                            ], True ),
                                            ( DictValuesField("states_history"),
                                            [
                                                SkinnyCallStates.Hold
                                            ], True )
                                          ],

            SkinnyCallAttrs.Conference  : [], # TODO

            SkinnyCallAttrs.Park        : [] # TODO
        })

def make_dict(values):
    return dict([(ind, v) for ind, v in enumerate(values)])

print
keys_list = call_type_classifier.get_values( "keys_history" )
print "keys: %s" % keys_list

print
states_list = call_type_classifier.get_values( "states_history" )
print "states: %s" % states_list

print
test_calls = []

test_call = CallInfo(SkinnyCallType.OUTBOUND_CALL)
test_call.callid = 1
test_call.states_history = make_dict([SkinnyCallStates.OffHook, SkinnyCallStates.Proceeding, SkinnyCallStates.RingOut, SkinnyCallStates.Connected, SkinnyCallStates.OnHook])
test_call.keys_history = make_dict([SkinnyKeyEvents.NewCall, SkinnyKeyEvents.EndCall])
test_calls.append(test_call)

test_call = CallInfo(SkinnyCallType.INBOUND_CALL)
test_call.callid = 2
test_call.states_history = make_dict([SkinnyCallStates.RingIn, SkinnyCallStates.OnHook])
test_call.keys_history = make_dict([])
test_calls.append(test_call)

test_call = CallInfo(SkinnyCallType.INBOUND_CALL)
test_call.callid = 3
test_call.states_history = make_dict([SkinnyCallStates.RingIn, SkinnyCallStates.OffHook, SkinnyCallStates.Connected, SkinnyCallStates.OnHook])
test_call.keys_history = make_dict([SkinnyKeyEvents.Answer])
test_calls.append(test_call)

test_call = CallInfo(SkinnyCallType.INBOUND_CALL)
test_call.callid = 4
test_call.states_history = make_dict([SkinnyCallStates.RingIn, SkinnyCallStates.OffHook, SkinnyCallStates.Connected])
test_call.keys_history = make_dict([SkinnyKeyEvents.Answer])
test_calls.append(test_call)

for call in test_calls:
    call_attrs = call_type_classifier.classify_object(call)

    print "[classify_call] call: %s, call attrs: %s (%s)" % (call.callid, hex(call_attrs), SkinnyCallAttrs.str(call_attrs))


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


session_classifier = FieldClassifier({

          SkinnySessionFlags.KeepAlive  : [( ArrayField("_seen_msgs"), 
                                            [
                                                0x0000, # SkinnyMessageKeepAlive 
                                            ], True )],

          SkinnySessionFlags.KeepAliveAck: [( ArrayField("_seen_msgs"), 
                                            [
                                                0x0100, # SkinnyMessageKeepAliveAck 
                                            ], True )],

          SkinnySessionFlags.Phone      : [( ArrayField("_seen_msgs"), 
                                            [
                                                0x0111, # SkinnyMessageCallState 
                                                0x014a, # SkinnyMessageCM5CallInfo
                                                0x0026, # SkinnyMessageSoftKeyEvent 
                                            ], True )],

          SkinnySessionFlags.MTP        : [( ArrayField("_seen_msgs"), 
                                            [
                                                0x008A, # SkinnyMessageStartMediaTransmission
                                                0x0154, # SkinnyMessageStartMediaTransmissionAck
                                                0x008B, # SkinnyMessageStopMediaTransmission

                                                0x0105, # SkinnyMessageOpenReceiveChannel
                                                0x0022, # SkinnyMessageOpenReceiveChannelAck
                                                0x0106, # SkinnyMessageCloseReceiveChannel

                                                0x011C, # SkinnyMessageStartMediaFailureDetection
                                                0x002A  # SkinnyMessageMediaTransmissionFailure
                                            ], True ),

                                           ( ArrayField("_seen_msgs"), 
                                            [
                                                0x0111, # SkinnyMessageCallState 
                                                0x014A, # SkinnyMessageCM5CallInfo
                                                0x0026, # SkinnyMessageSoftKeyEvent 
                                                0x0001, # SkinnyMessageRegister
                                                0x0081, # SkinnyMessageRegisterAck
                                            ], False )],
      })


session_ctxs = []


# keep alive + keep alive ack
session_ctx = SessionClassifyContext()
session_ctx.set_capture_msgs([
        0x0000, # SkinnyMessageKeepAlive 
        0x0100, # SkinnyMessageKeepAliveAck 
    ])
session_ctx.test_msg(0x0000) # SkinnyMessageKeepAlive 
session_ctx.test_msg(0x0001) # SkinnyMessageRegister
session_ctx.test_msg(0x0100) # SkinnyMessageKeepAliveAck 
session_ctx.test_msg(0x0100) # SkinnyMessageKeepAliveAck 
session_ctxs.append(session_ctx)


# phone
session_ctx = SessionClassifyContext()
session_ctx.set_capture_msgs([
        0x0111, # SkinnyMessageCallState 
        0x0026, # SkinnyMessageSoftKeyEvent
        0x0022, # SkinnyMessageOpenReceiveChannelAck
        0x002A  # SkinnyMessageMediaTransmissionFailure        
    ])
session_ctx.test_msg(0x0111) # SkinnyMessageCallState
session_ctx.test_msg(0x0026) # SkinnyMessageSoftKeyEvent
session_ctxs.append(session_ctx)


# mtp
session_ctx = SessionClassifyContext()
session_ctx.set_capture_msgs([
        0x008A, # SkinnyMessageStartMediaTransmission
        0x0022, # SkinnyMessageOpenReceiveChannelAck
        0x002A, # SkinnyMessageMediaTransmissionFailure
        0x0001, # SkinnyMessageRegister
    ])
session_ctx.test_msg(0x008A) # SkinnyMessageStartMediaTransmission
session_ctx.test_msg(0x0022) # SkinnyMessageOpenReceiveChannelAck
#session_ctx.test_msg(0x0001) # SkinnyMessageRegister
session_ctxs.append(session_ctx)


for ctx in session_ctxs:
    session_attrs = session_classifier.classify_object(ctx)

    print "[classify_call] session ctx: %s, session attrs: %s (%s)" % (
        ctx, hex(session_attrs), SkinnySessionFlags.str(session_attrs))


print

print "'%s'" % SkinnySessionFlags.str( 
    SkinnySessionFlags.KeepAlive | SkinnySessionFlags.KeepAliveAck | SkinnySessionFlags.Phone | SkinnySessionFlags.MTP)

print "'%s'" % SkinnySessionFlags.str( 
    SkinnySessionFlags.KeepAlive | SkinnySessionFlags.Phone | SkinnySessionFlags.MTP)

print "'%s'" % SkinnySessionFlags.str( 
    SkinnySessionFlags.MTP)

print "'%s'" % SkinnySessionFlags.str( 
    SkinnySessionFlags.Phone)

print "'%s'" % SkinnySessionFlags.str( 
    SkinnySessionFlags.No)


print

print "'%s'" % SkinnyCallAttrs.str( 
    SkinnyCallAttrs.Established | SkinnyCallAttrs.Interrupted | SkinnyCallAttrs.P2P | SkinnyCallAttrs.Transfer | SkinnyCallAttrs.ExternalNum)

print "'%s'" % SkinnyCallAttrs.str( 
    SkinnyCallAttrs.No)


print "'%s'" % SkinnyCallAttrs.str( 9 )