from enum import *
import sys, datetime, time
from scapy.contrib.skinny import *

from constants import *
from common_types import BitEnum, ErrorType2, JsonSerializable, Ownable, MediaEndpoint
from rtp_flow import *


class SkinnyCallAttrs(BitEnum):
    No          = 0
    Established = 1 << 0        #  state & Connected != 0                               # +
    ExternalNum = 1 << 1        #                                                       # +
    Interrupted = 1 << 2        #  state & Hold != 0                                    # +
    P2P         = 1 << 3        #  key & (Transfer | Confrn | Join) == 0                # +
    Forward     = 1 << 4        #  key & CFwdAll != 0
    Transfer    = 1 << 5        #  key & (Transfer | Resume) != 0 AND state & Hold != 0     # +
    Conference  = 1 << 6        #  key & (Join | Confrn) != 0
    Park        = 1 << 7        #  key & Park != 0

    @staticmethod
    def str(attrs):
        return reduce(
            lambda x,y : x + (" " if x != "" and y != "" else "") + y,
            map( (lambda attr: skinny_call_attrs[attr] if (attr & attrs) == attr else ""), skinny_call_attrs.keys() )
        )

skinny_call_attrs = {
    SkinnyCallAttrs.No : "",
    SkinnyCallAttrs.Established : "Established",
    SkinnyCallAttrs.ExternalNum : "ExternalNum",
    SkinnyCallAttrs.Interrupted : "Interrupted",
    SkinnyCallAttrs.P2P : "P2P",
    SkinnyCallAttrs.Forward : "Forward",
    SkinnyCallAttrs.Transfer : "Transfer",
    SkinnyCallAttrs.Conference : "Conference",
    SkinnyCallAttrs.Park : "Park",
}


# values mapped to skinny_call_type
class SkinnyCallType(IntEnum):
    INBOUND_CALL    = 1
    OUTBOUND_CALL   = 2 
    FORWARD_CALL    = 3


# values mapped to skinny_callstates keys
class SkinnyCallStates(IntEnum):
    OffHook    = 0x01
    OnHook     = 0x02
    RingOut    = 0x03
    RingIn     = 0x04
    Connected  = 0x05
    Busy       = 0x06
    Hold       = 0x08
    Proceeding = 0x0C
    CallRemoteMultiline = 0x0D


# values mapped to skinny_key_events
class SkinnyKeyEvents(IntEnum):
    Redial          = 0x01
    NewCall         = 0x02
    Hold            = 0x03
    Transfer        = 0x04
    CFwdAll         = 0x05
    CFwdNoAnswer    = 0x07
    Backspace       = 0x08
    EndCall         = 0x09
    Resume          = 0x0A
    Answer          = 0x0B
    Info            = 0x0C
    Confrn          = 0x0D
    Park            = 0x0E
    Join            = 0x0F 
    MettMeConfrn    = 0x10
    CallPickUp      = 0x11
    GrpCallPickUp   = 0x12

    MaxKnown        = 0x13


class ParseState(IntEnum):
    NOT_SET = 0
    OPENED = 1
    CLOSED = 2


parse_states = {
    ParseState.NOT_SET : "NOT_SET",
    ParseState.OPENED : "OPENED",
    ParseState.CLOSED : "CLOSED",
}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class CallInfo(JsonSerializable, Ownable, MediaEndpoint):
    def __init__(self, call_type = SkinnyCallType.INBOUND_CALL, data = None):
        Ownable.__init__(self)

        if data:
            self.__dict__ = data

            for rtpf in self.rtp_flows.values():
                rtpf.set_owner(self)
        else:
            self.st_time = 0    # by ParseState.OPENED
            self.end_time = 0   # by ParseState.CLOSED

            self.callid = 0
            self.line = 0
            self.call_type = call_type 

            key = SkinnyCallStates.Proceeding if call_type == SkinnyCallType.OUTBOUND_CALL else SkinnyCallStates.RingIn
            self.party_info = {
                SkinnyCallStates.Connected : None,
                key : None
            }

            # time => value
            self.states_history = {}
            self.keys_history = {}

            self.statistics_res = None

            self.parse_state = ParseState.NOT_SET
            self.pstates_history = []       
            #self.transfer_vs = None # TODO:?

            self.call_errors = ErrorType2.No
            self.call_attrs = SkinnyCallAttrs.No
            # ppid => RtpFlow
            self.rtp_flows = {}


    def set_call_attribute(self, attr_bit):
        self.call_attrs |= attr_bit


    def get_call_attributes(self):
        return self.call_attrs


    def set_call_error(self, error):
        self.call_errors |= error


    def get_rtp_flow(self, ppid, create_if_not_exist = True):
        exist = self.rtp_flows.has_key(ppid)

        if not exist and create_if_not_exist:
            self.rtp_flows[ppid] = RtpFlow(ppid)
            exist = not exist

        return self.rtp_flows[ppid] if exist else None


    def get_party_end(self, name):
        res = None
        if name == "local" or name == "remote":
            party_info = self.party_info[SkinnyCallStates.Connected]
            if party_info == None:
                for state in self.party_info.keys():
                    if state != SkinnyCallStates.Connected:
                        party_info = self.party_info[state]
                        break

            if party_info != None:
                if self.call_type == SkinnyCallType.INBOUND_CALL or self.call_type == SkinnyCallType.FORWARD_CALL:
                    res = party_info["to"] if name == "local" else party_info["from"]

                elif self.call_type == SkinnyCallType.OUTBOUND_CALL:
                    res = party_info["from"] if name == "local" else party_info["to"]
        return res

    def get_state(self):
        return self.states_history[max(self.states_history.keys())] if len(self.states_history) > 0 else None

    def update_pstate(self, pstate, time = None):
        self.parse_state = pstate
        self.pstates_history.append(pstate)
        
        #print "[update_pstate] CallInfo: [%s] line = %s, parse_state = %s, call_type = %s" % (self.callid, self.line, self.parse_state, self.call_type)

        if time != None:
            if pstate == ParseState.OPENED:
                if self.st_time == 0:
                    self.st_time = time

            elif pstate == ParseState.CLOSED:
                self.end_time = time


    def show_call_details(self, compact = False, label = '', padding = ''):
        if compact:
            if label != '':
                print label
            #print 'CallInfo: [%s] line = %s, parse_state = %s, call_type = %s' % (self.callid, self.line, self.parse_state, self.call_type)
            
            print padding,  '[ %s ] line: %s, call type: %s' % (
                self.callid, 
                self.line, 
                skinny_call_type[self.call_type] )
            
            print padding, '[ %s ]' % SkinnyCallAttrs.str(self.call_attrs)

            print padding, '[%s - %s]' % (datetime.datetime.fromtimestamp(self.st_time), datetime.datetime.fromtimestamp(self.end_time))
            
            state = SkinnyCallStates.Connected
            party_info = self.party_info[state];
            if party_info != None:
                print '\t[%s] #%s (%s) --> #%s (%s)' % (
                    skinny_callstates[state],
                    party_info["from"][0],              
                    party_info["from"][1],
                    party_info["to"][0],
                    party_info["to"][1] if party_info["to"][0] != "" else "" # TODO: drop this ugly '\u20ac' hack
                )

            print padding, map( (lambda time : skinny_callstates[ self.states_history[time] ]), sorted(self.states_history.keys()) )
            print padding, map( (lambda time : skinny_key_events[ self.keys_history[time] ] if self.keys_history[time] in skinny_key_events else str(self.keys_history[time]) ), sorted(self.keys_history.keys()) )
        else:
            print PRINT_DELIMETER
            if self.call_errors > 0 and self.call_errors <= ErrorType2.MaxCritical:
                print "****** CALL ERROR (crititical) ******"
            #print 'CallInfo: [%s] line = %s, parse_state = %s, call_type = %s' % (self.callid, self.line, self.parse_state, self.call_type)
            
            print "[ %s ] line: %s, call type: %s, pstates: %s" % (
                self.callid, 
                self.line, 
                skinny_call_type[self.call_type],
                map( (lambda pstate : "".join(parse_states[pstate])), self.pstates_history )
            )
            print "[ %s ]" % SkinnyCallAttrs.str(self.call_attrs)

            print '[%s - %s]' % (datetime.datetime.fromtimestamp(self.st_time), datetime.datetime.fromtimestamp(self.end_time))
            
            for state in self.party_info.keys():
                party_info = self.party_info[state];
                if party_info != None:
                    print '[%s] #%s (%s) --> #%s (%s)' % (
                        skinny_callstates[state],
                        party_info["from"][0],              
                        party_info["from"][1],
                        party_info["to"][0],
                        party_info["to"][1] if party_info["to"][0] != "" else "" # TODO: drop this ugly '\u20ac' hack
                    )

            print map( (lambda time : skinny_callstates[ self.states_history[time] ]), sorted(self.states_history.keys()) )
            print map( (lambda time : skinny_key_events[ self.keys_history[time] ] if self.keys_history[time] in skinny_key_events else str(self.keys_history[time]) ), sorted(self.keys_history.keys()) )

            if len(self.rtp_flows.keys()) > 0:
                print "RTP:"
                for rtp_info in self.rtp_flows.values():
                    print '\t', rtp_info

            # if self.transfer_vs != None:
            #   if self.call_type == SkinnyCallType.INBOUND_CALL:
            #       print 'transfered to: %s' % self.transfer_vs
            #   elif self.call_type == SkinnyCallType.OUTBOUND_CALL:
            #       print 'assigned transfer: %s' % self.transfer_vs

    #def show_rtp_stats(self):
        if self.statistics_res:
            print "RTP stats:\n\t", self.statistics_res

        return self.call_errors


    def dump_media_endpoint(self, label):
        return self.show_call_details(compact = True, label = label, padding = '\t')


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


