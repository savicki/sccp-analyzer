
from common_types import SessionBase, SessionIterator, SkinnySessionFlags
from field_classifier import *


def create_session_classifier():
    return FieldClassifier({

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

                                                # phone-specific msgs
                                                0x0110, # SkinnyMessageSelectSoftKeys # captured during phone registration.
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
                                                # phone-specific msgs
                                                0x0111, # SkinnyMessageCallState 
                                                0x014A, # SkinnyMessageCM5CallInfo
                                                0x0026, # SkinnyMessageSoftKeyEvent
                                            ], False )],
      })


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class SessionClassifyContext(SessionBase):
    def __init__(self):
        self._capture_msgs = []
        self._seen_msgs = [] # unique messages

    def set_capture_msgs(self, msgs):
        self._capture_msgs = msgs
        print '[set_capture_msgs] _capture_msgs: %s (%s)' % (msgs, len(msgs))

    def test_msg(self, msg):
        stop_processing = False
        if msg in self._capture_msgs and msg not in self._seen_msgs:
            self._seen_msgs.append(msg)
            stop_processing = len(self._capture_msgs) == len(self._seen_msgs)

        return stop_processing

    def get_match_stats(self):
        return ( len(self._seen_msgs), len(self._capture_msgs) )


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class SessionClassifier(SessionIterator):

    def open_session(self, context):
        SessionIterator.open_session(self, context)
        classify_ctx = self._context[0]  # SessionClassifyContext
        classifier = self._context[1]  # FieldClassifier

        classify_ctx.set_capture_msgs(classifier.get_values("_seen_msgs"))

    def process_msg(self, sccp_msg, fdir, pkt_time):
        # print "[SessionClassifier::process_msg] msg: %s, len: %s + 12 bytes, ver.: %s" % (
        #     hex(sccp_msg.msg), sccp_msg.len, sccp_msg.res)

        return self._context[0].test_msg(sccp_msg.msg)

    def close_session(self):
        classify_ctx = self._context[0]
        classifier = self._context[1]

        print '[close_session] get_match_stats()=', classify_ctx.get_match_stats()

        session_attrs = classifier.classify_object(classify_ctx)
        
        return session_attrs