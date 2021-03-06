
from enum import *
import json, re

from common_types import SkinnySessionFlags, SessionBase, SessionIterator, SessionHandler, JsonSerializable, RtpFlowsContainer, ErrorType2, SkinnySessionFlags2
from field_classifier import *
from call_info import *


def create_call_type_classifier():
    return FieldClassifier({

            SkinnyCallAttrs.Established : [( DictValuesField('states_history'), 
                                            [
                                                SkinnyCallStates.Connected
                                            ], True )],

            SkinnyCallAttrs.ExternalNum : [], # TODO

            SkinnyCallAttrs.Interrupted : [( DictValuesField('states_history'), 
                                            [
                                                SkinnyCallStates.Hold
                                            ], True )],

            SkinnyCallAttrs.P2P         : [( DictValuesField('keys_history'), 
                                            [
                                                SkinnyKeyEvents.Transfer, 
                                                SkinnyKeyEvents.Confrn, 
                                                SkinnyKeyEvents.Join
                                            ], False )],

            SkinnyCallAttrs.Forward     : [], # TODO

            SkinnyCallAttrs.Transfer    : [
                                            ( DictValuesField('keys_history'),  
                                            [
                                                SkinnyKeyEvents.Transfer, 
                                                SkinnyKeyEvents.Resume
                                            ], True ),
                                            ( DictValuesField('states_history'),
                                            [
                                                SkinnyCallStates.Hold
                                            ], True )
                                          ],

            SkinnyCallAttrs.Conference  : [], # TODO

            SkinnyCallAttrs.Park        : [] # TODO
        })


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class PhoneSession(SessionBase, JsonSerializable, RtpFlowsContainer):
    def __init__(self, data = None):
        SessionBase.__init__(self)

        if data:
            self.__dict__ = data

            for call in self.calls.values():
                call.set_owner(self)

        else:
            self.__call_classifier = create_call_type_classifier()

            self.calls_summary = {}

            self.register = {
                # per line
                'number' : {},
                'name' : {},
                # per line, if line res. msg info not captured
                'tries' : {},

                # fields available only if 'SkinnySessionFlags2.FromBegining' bit set
                'info' : {
                    'max_rtp': None, 
                    'firmware_load_name': None, 
                    'protocol_ver': None, 
                    'max_lines': None, 
                    'mac_addr': None, 
                    'device_type': None, 
                    'max_confs': None, 
                    'station_ip': None
                },

                # fields available only if 'SkinnySessionFlags2.FromBegining' bit set
                'protocol' : {
                    'requested' : None,
                    'max_supported' : None,
                    'used' : None,
                }
            }

            self.derived_info = {
                # from flow tuple, double checked from register info, if 'SkinnySessionFlags2.FromBegining' bit set
                'ip' : None, 
                # from ORCa, if 'SkinnySessionFlags2.RealIpKnown' bit set
                'real_ip' : None, 
                'session_flags' : SkinnySessionFlags2.No,
                # this include errors not bound to particular call, e.g. 'ErrorType2.SoftKeyUnknown'
                'session_errors' : ErrorType2.No,
                # TODO: error_code => [artifacts], not implemented now
                'session_errors_info' : {} 
            }

            # set before this session opening
            self.ip_info = None
            
            # list of (callid, completed) tuples, 
            # actually only during pcap-session reconstruction 
            self.calls_history = []
            self.__next_print_ind = 0

            # key is 'callid'
            self.calls = {}
            # time => soft_key
            self.callfree_soft_keys = {} # must be empty if no opened calls on session closure
            ### self.pending_transfers = [] # not implemented

            self.__bypass = False

            #
            # for session self-tests, before session closure
            #

            # callid => call_summary
            self.__test_calls = {

            }


    def classify_call(self, call_info):
        if self.__call_classifier:
            call_attrs = self.__call_classifier.classify_object(call_info)
            ### print '[classify_call] call: %s, call attrs: %s' % (call_info.callid, hex(call_attrs))
            call_info.set_call_attribute(call_attrs)


    # by RingIn, OffHook CS
    def test_start_call(self, callid):
        if callid in self.__test_calls.keys():
            return

        self.__test_calls[callid] = {
            'states' : [],
            'keys' : [],
            'completed': False
        }


    # by OnHook CS
    def test_end_call(self, callid):
        if callid not in self.__test_calls.keys():
            return

        self.__test_calls[callid]['completed'] = True


    def test_append_call_state(self, callid, call_state):

        if callid not in self.__test_calls.keys():
            return

        self.__test_calls[callid]['states'].append(call_state)


    def test_append_key(self, callid, key):

        if callid not in self.__test_calls.keys():
            return

        self.__test_calls[callid]['keys'].append(key)


    def test_do(self):
        
        # completed only calls
        seen_calls = self.__test_calls.keys()
        seen_calls.sort()

        # completed and in-progress calls
        processed_calls = self.calls.keys()
        processed_calls.sort()

        #if len(processed_calls) > 0:
        print PRINT_DELIMETER

        confirmed_calls = 0

        for callid, call_info in self.calls.items():
            if callid in seen_calls:
                if len(call_info.states_history) == len(self.__test_calls[callid]['states']):
                    seen_completed = self.__test_calls[callid]['completed']
                    real_completed = call_info.parse_state == ParseState.CLOSED

                    if seen_completed == real_completed:
                        confirmed_calls += 1
                    else:
                        print 'callid %s : seen_completed: %s, real_completed: %s' % (seen_completed, real_completed, callid)
                else:
                    print 'callid %s : len mismatched: real %s vs test-seen %s' % (
                        callid, len(call_info.states_history), len(self.__test_calls[callid]['states']))
                    print call_info.states_history
            else:
                print 'callid %s not in seen_calls' % callid

        if confirmed_calls != len(seen_calls) or len(processed_calls) != len(seen_calls):
            print 'test seen: %s' % seen_calls
            print 'processed: %s' % processed_calls
            raise ValueError( '[test_do] processed %s total calls, seen %s, but completely confirmed %s' % (
                len(processed_calls), len(seen_calls), confirmed_calls) )
        else:
            print '[test_do] processed %s total calls, seen and confirmed %s' % (
                len(processed_calls), confirmed_calls)

        print PRINT_DELIMETER


    def get_first_call(self):
        call = None
        if len(self.calls_history) > 0:
            callid = self.calls_history[0][0]
            call = self.calls[str(callid)]
        return call

    def get_last_call(self):
        call = None
        if len(self.calls_history) > 0:
            callid = self.calls_history[len(self.calls_history) - 1][0]
            call = self.calls[str(callid)]
        return call


    def set_session_error(self, error, error_ctx = None):
        self.derived_info['session_errors'] |= error
        self.__bypass = self.derived_info['session_errors'] <= ErrorType2.MaxCritical


    def get_session_errors(self):
        return self.derived_info['session_errors']


    def is_bypass_on(self):
        return self.__bypass


    def get_proto_version(self):
        return self.register['protocol']['used']


    def set_register_info(self, info):
        ### print '[set_register_info]'

        if self.register['info']['mac_addr']:
            raise ValueError('already registered')

        self.register['info'] = info
        self.register['protocol']['requested'] = info['protocol_ver']

        self.derived_info['session_flags'] |= SkinnySessionFlags2.FromBegining
        if self.derived_info['ip'] != info['station_ip']:
            raise ValueError('station_ip != flow.src_ip : %s != %s' % (info['station_ip'], self.derived_info['ip']))


    def get_register_info_all(self):
        return self.register


    def set_register_ack_info(self, info):
        self.register['protocol']['max_supported'] = info['max_protocol_ver']


    def set_ip_port_info(self, version):
        self.register['protocol']['used'] = version


    def set_line_info(self, info):
        line = info[0]
        ### print '[set_line_info] line: %s' % line

        if line in self.register['number'].keys():
            raise ValueError('line \'%s\' already initialzed by CCM' % line)
        self.register['number'][line] = info[1]

        if line in self.register['name'].keys():
            raise ValueError('line \'%s\' already initialzed by CCM' % line)
        self.register['name'][line] = info[2]

        self.register['tries'][line] = 4


    # return True if info update (for all lines) completed, False otherwise
    def update_line_info(self, callid):
        completed = False

        if self.register['tries'] != None:
            call_info = self.calls[callid]
            line = call_info.line

            #print call_info.line, self.register['number'].keys()
            #print self.register['tries'].keys()

            tried = self.register['tries'][line] if line in self.register['tries'].keys() else 0

            if tried < 4:
                real_owner = call_info.get_party_end('local')

                if real_owner != None:
                    
                    if line not in self.register['number'].keys():
                        self.register['number'][line] = real_owner[0]

                    if line not in self.register['name'].keys():
                        self.register['name'][line] = real_owner[1]

                    if self.register['number'][line] == real_owner[0] and self.register['name'][line] == real_owner[1]:
                        tried += 1
                    else:
                        tried = 0
                        print '**** reset tried counter!'

                self.register['tries'][line] = tried


            lines_done = 0
            for line in self.register['number'].keys():
                if self.register['tries'][line] == 4:
                    lines_done += 1

            if lines_done == len(self.register['number'].keys()):
                self.register['tries'] = None
                completed = True

        ### print '[update_line_info] completed: %s' % completed

        return completed


    def show_session_details(self):
        print PRINT_DELIMETER

        #
        # don't trust 'end_time' value - it's 'ended' with 1st completed call,
        # but completely valid in .json
        #
        print '[msg: %s - %s] [ip: %s - %s] [ %s ] [ %s ] \n' % (
            datetime.datetime.fromtimestamp(self.s_info.st_time),
            datetime.datetime.fromtimestamp(self.s_info.end_time),

            datetime.datetime.fromtimestamp(self.ip_info.st_time),
            datetime.datetime.fromtimestamp(self.ip_info.end_time),

            self.s_info.filename,
            'in middle' if (self.derived_info['session_flags'] & SkinnySessionFlags2.FromBegining) == 0 else 'from beginning'
        )
        info = self.register['info']
        protocol = self.register['protocol']
        
        print 'Device: %s, ip: %s (mac: %s), max RTPs: %s, proto: requested: %s, supported.max: %s, used: %s' % (

            hex(info['device_type'])    if info['device_type']          else '<unknown>', 
            info['station_ip']          if info['station_ip']           else self.derived_info['ip'], 
            info['mac_addr']            if info['mac_addr']             else '<unknown>',
            info['max_rtp']             if info['max_rtp']              else '<unknown>',
            protocol['requested']       if protocol['requested']        else '<unknown>',
            protocol['max_supported']   if protocol['max_supported']    else '<unknown>',
            protocol['used']            if protocol['used']             else '<unknown>'
        )

        for line in self.register['number'].keys():
            number = self.register['number'][line]
            if number != '':
                print 'Line [%s] : #%s / \'%s\'' % (
                        line,
                        number,
                        self.register['name'][line] if self.register['name'].has_key(line) else ''
                    )

        #
        # drop empty lines & numbers
        #
        self.register['number'] = {
            line: num for line, num in self.register['number'].items() if num.strip() != '' 
        }

        self.register['name'] = {
            line: name for line, name in self.register['name'].items() if name.strip() != '' 
        }

        return False # no errors


    def open_phone_session(self):
        #
        # (1) open session header
        #
        self.begin_call(0)

        #
        # (2)setup derived info
        #
        self.derived_info['ip'] = self.ip_info.local_ip


    def complete_session_header(self):

        ### print '[complete_session_header]'
        self.complete_call(0)
        

    def begin_call(self, callid):
        # if callid == 0:
        #   raise ValueError('call id can't be 0')

        self.calls_history.append( (callid, False) )

        ### print '[begin_call] callid = %s, index = %s' % (callid, len(self.calls_history) - 1)


    # This call almost [due to OnHook state] ready. 
    # Current call will be printed after next one (if any) will be completed.
    # We assume this-call RTP stats will appear before next call ends.
    def complete_call(self, callid):
        if (callid, False) not in self.calls_history:
            raise ValueError('callid \'%s\' not in history' % callid)

        limit_ind = self.calls_history.index( (callid, False) )

        ### print '[complete_call] callid = %s, limit_ind = %s' % (callid, limit_ind)
        
        self.calls_history[limit_ind] = (callid, True)

        DELTA = 2

        # print previously ended items up to @DELTA closer to this
        while limit_ind - self.__next_print_ind >= DELTA:

            if self.calls_history[self.__next_print_ind][1] == False:
                break;

            #print '**** go: __next_print_ind = %s' % self.__next_print_ind

            callid = self.calls_history[self.__next_print_ind][0]

            print_item = self.calls[callid] if callid > 0 else self

            if isinstance(print_item, CallInfo):
                res, call_errors = print_item.close_call()
                if res:
                    self.derived_info['session_errors'] |= call_errors
                    print_item.show_call_details()

            else:
                print_item.show_session_details()

            self.__next_print_ind += 1


    def close_phone_session(self):
        limit_ind = len(self.calls_history)
        ### print '[close_phone_session] limit_ind = %s' % limit_ind
        
        #
        # (1) print previously ended items and collect summary status
        #
        while self.__next_print_ind < limit_ind:

            callid = self.calls_history[self.__next_print_ind][0]

            # TODO: raise error if call not ended.

            print_item = self.calls[callid] if callid > 0 else self
            
            if isinstance(print_item, CallInfo):
                if self.__next_print_ind + 1 == limit_ind:
                    print_item.call_attrs |= SkinnyCallAttrs.LastCall

                res, call_errors = print_item.close_call()
                if res:
                    self.derived_info['session_errors'] |= call_errors
                    print_item.show_call_details()

                # print '********'
                # print json.dumps(print_item.__dict__, cls=CallInfoJsonEncoder, indent=4)
                # print '********'
            else:
                print_item.show_session_details()

            self.__next_print_ind += 1


        #
        # (2) perform self-tests
        #
        self.test_do()

        
        #
        # (3) make summary info for session
        #
        self.build_summary()

        return self.derived_info['session_errors']


    def build_summary(self):

        print '\nSummary for phone session:\n'

        #
        # walk array types
        #

        uniq_keys = []
        for call_info in self.calls.values():
            for key in call_info.keys_history.values():
                if key not in uniq_keys:
                    uniq_keys.append(key)

        self.calls_summary['soft_keys'] = uniq_keys
        print 'soft keys:', uniq_keys


        uniq_states = []
        for call_info in self.calls.values():
            for state in call_info.states_history.values():
                if state not in uniq_states:
                    uniq_states.append(state)

        self.calls_summary['call_states'] = uniq_states
        print 'call states:', uniq_states


        uniq_ctypes = []
        for call_info in self.calls.values():
            if call_info.call_type not in uniq_ctypes:
                uniq_ctypes.append(call_info.call_type)

        self.calls_summary['call_types'] = uniq_ctypes
        print 'call types:', uniq_ctypes


        #
        # walk bit types
        #

        sum_call_attrs = SkinnyCallAttrs.No
        for call_info in self.calls.values():
            sum_call_attrs |= call_info.get_call_attributes()

        self.calls_summary['call_attrs'] = sum_call_attrs
        print 'call attrs:', SkinnyCallAttrs.str(sum_call_attrs)


        #
        # walk error types
        #

        sum_call_errors = ErrorType2.No
        for call_info in self.calls.values():
            sum_call_errors |= call_info.call_errors

        self.calls_summary['call_errors'] = sum_call_errors
        print 'call errors:', ErrorType2.str(sum_call_errors)


    def get_json_dict(self):
        dict_res = super(PhoneSession, self).get_json_dict()

        del dict_res['calls_history'][0]
        del dict_res['callfree_soft_keys']

        return dict_res


    def get_rtp_flows(self):
        flows_arr = [call.rtp_flows.values() for call in self.calls.values()]
        return reduce( lambda x, y : x + y, flows_arr ) if len(flows_arr) > 0 else []


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class PhoneSessionIterator(SessionIterator, SessionHandler):

    def __init__(self):
        SessionIterator.__init__(self)
        SessionHandler.__init__(self)

        SessionHandler._init_handlers(self, self.__class__.__name__)


    def open_session(self, context):
        SessionIterator.open_session(self, context) 
        self._context.open_phone_session()


    def close_session(self):

        errors = self._context.close_phone_session()

        return errors


    def process_msg(self, sccp_msg, fdir, pkt_time):
        stop_processing = False
        # print '[PhoneSessionIterator::process_msg] msg: %s, len: %s + 12 bytes, ver.: %s, dir: %s, time: %s' % (
        #     hex(sccp_msg.msg), sccp_msg.len, sccp_msg.res, fdir, pkt_time)
        
        if not self._context.s_info.st_time: 
            self._context.s_info.st_time = pkt_time
        self._context.s_info.end_time = pkt_time

        if self._context.is_bypass_on() == False:
            if self._handlers.has_key(sccp_msg.msg):
                func = self._handlers[sccp_msg.msg]
            
                #print 'process msg: %s (%s), dir: %s' % (skinny_messages_cls[sccp_msg.msg], hex(sccp_msg.msg), fdir)
                #sccp_msg.show()
                stop_processing = func(sccp_msg, fdir, pkt_time)

        return stop_processing


    def __assert(self, assert_exp, failed_msg = None):
        if assert_exp == False:
            extra = ( '. Details : ' + str(failed_msg) ) if failed_msg != None else ''
            raise ValueError('assertion failed' + extra)


    def __test_call_info_alive(self, call_info, msg_id, raise_exc = True):
        alive = (call_info.parse_state != ParseState.CLOSED)
        if alive == False and raise_exc:
            raise ValueError('call_info \'%s\' in CLOSED (%s) state while processing \'%s\' msg' % (
                call_info.callid, 
                call_info.parse_state,
                skinny_messages_cls[msg_id])
            )

        return alive

    def __test_call_info_state(self, call_info, msg_id, parse_state, equal):
        res = (call_info.parse_state == parse_state) if equal else (call_info.parse_state != parse_state)
        if (res == False):
            raise ValueError("Assert 'call_info '%s' %s in '%s' state' failed, msg: '%s'" % 
                (call_info.callid, 
                 '' if equal else 'NOT',
                 parse_state,
                 skinny_messages_cls[msg_id]
                )
            )


    #
    # to CCM, Dir.DIR_ORIG
    #


    def __process__0x0001__register_msg(self, msg, fdir, pkt_time): # TODO: must be turn-of-able

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageRegister]
        #sub_msg.show()

        reg_info = sub_msg.get_register_info()

        if reg_info != None:
            self._context.set_register_info(reg_info)


    def __process__0x0002__ip_port_msg(self, msg, fdir, pkt_time): # TODO: must be turn-of-able

        # we need only header version
        #self._test_no_raw_layer(msg)

        self._context.set_ip_port_info(msg.res)

        ver = self._context.get_proto_version()
        if ver > 0x12: # type A
            self._context.set_session_error( ErrorType2.NotSupportedProto )


    def __SKIP__process__0x0006__off_hook_msg(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageOffHook]
        #sub_msg.show()

        self.__assert(sub_msg.lineInstance == 0 and sub_msg.callIdentifier == 0)


        call_info = CallInfo(SkinnyCallType.OUTBOUND_CALL)
        call_info.update_pstate( ParseState.LOCAL_OPENED, pkt_time )

        if self._context.calls.has_key(call_info.callid):
            print '*** 104 = %s' % self._context.calls[call_info.callid].st_time
            raise ValueError('callid %s already exist [time=%s] [key=%s(%s)]' % (call_info.callid, pkt_time, skinny_key_events[sub_msg.key], sub_msg.key))

        # add new partially-initialized (callid == 0) call,
        # but don't append to history
        self._context.calls[call_info.callid] = call_info


    def __SKIP__process__0x0007__on_hook_msg(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageOnHook]
        #sub_msg.show()

        self.__assert(sub_msg.lineInstance == 0 and sub_msg.callIdentifier == 0)


    # def __SKIP__process__0x000B__line_stat_req(self, msg, fdir, pkt_time): # TODO: must be turn-of-able
        
    #   self._test_no_raw_layer(msg)

    #   sub_msg = msg[SkinnyMessageLineStatReq]
    #   #sub_msg.show()

    #   self._context.create_line_info(sub_msg.lineNumber)


    # def __SKIP__process__0x002D__reg_lines(self, msg, fdir, pkt_time): # TODO: must be turn-of-able
        
    #   self._test_no_raw_layer(msg)

    #   sub_msg = msg[SkinnyMessageRegisterAvailableLines]
    #   #sub_msg.show()

    #   if self._context.complete_line_info(sub_msg.linesNumber):
    #       self._context.complete_session_header(True)


    def __process__0x0026__soft_key_event(self, msg, fdir, pkt_time):
        call_info = None

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageSoftKeyEvent]
        #sub_msg.show()

        # if sub_msg.key == SkinnyKeyEvents.NEW_CALL or sub_msg.key == SkinnyKeyEvents.REDIAL:

        #   if sub_msg.key == SkinnyKeyEvents.REDIAL and self._context.calls.has_key(sub_msg.callid):
        #       call_info = self._context.calls[sub_msg.callid];

        #   else:
        #       call_info = CallInfo(SkinnyCallType.OUTBOUND_CALL)
        #       call_info.update_pstate( ParseState.LOCAL_OPENED, pkt_time )

        #       if self._context.calls.has_key(call_info.callid):
        #           print '*** 104 = %s' % self._context.calls[call_info.callid].st_time
        #           raise ValueError('callid %s already exist [time=%s] [key=%s(%s)]' % (call_info.callid, pkt_time, skinny_key_events[sub_msg.key], sub_msg.key))

        #       # add new partially-initialized (callid == 0) call,
        #       # but don't append to history
        #       self._context.calls[call_info.callid] = call_info
        #       print 'ADD [0] [time=%s] [key=%s(%s)]' % (pkt_time, skinny_key_events[sub_msg.key], sub_msg.key)

        # elif sub_msg.key == SkinnyKeyEvents.CONFRN or sub_msg.key == SkinnyKeyEvents.CFWDALL:
            
        #   if self._context.calls.has_key(sub_msg.callid):
        #       call_info = self._context.calls[sub_msg.callid]

        #   call_info_t = CallInfo(SkinnyCallType.OUTBOUND_CALL)
        #   call_info_t.update_pstate( ParseState.LOCAL_OPENED, pkt_time )

        #   if self._context.calls.has_key(call_info_t.callid):
        #       print '*** 104 = %s' % self._context.calls[call_info.callid].st_time
        #       raise ValueError('callid %s already exist [time=%s] [key=%s(%s)]' % (call_info_t.callid, pkt_time, skinny_key_events[sub_msg.key], sub_msg.key))

        #   self._context.calls[call_info_t.callid] = call_info_t
        #   print 'ADD [0] [time=%s] [key=%s(%s)]' % (pkt_time, skinny_key_events[sub_msg.key], sub_msg.key)

        # # TODO: support transfer multiple times??
        # elif sub_msg.key == SkinnyKeyEvents.TRANSFER:

        #   if self._context.calls.has_key(sub_msg.callid) == False:
        #       raise ValueError('callid %s not found' % sub_msg.callid)

        #   # print 'SkinnyKeyEvents.TRANSFER, callid = %s, transfers: %s' % (sub_msg.callid, len(self._context.pending_transfers))

        #   # for tid in self._context.pending_transfers:
        #   #   print '\t pending trans: %s' % tid

        #   # append key event to 'transfered' call's history
        #   call_info = self._context.calls[sub_msg.callid]

        #   if len(self._context.pending_transfers) == 0:
        #   #if call_info.call_type == SkinnyCallType.INBOUND_CALL:
        #       # expect 'transfer to' call on line
        #       call_info_t = CallInfo(SkinnyCallType.OUTBOUND_CALL)
        #       call_info_t.update_pstate( ParseState.LOCAL_OPENED, pkt_time )

        #       if self._context.calls.has_key(call_info_t.callid):
        #           print '*** 104 = %s' % self._context.calls[call_info.callid].st_time
        #           raise ValueError('callid %s already exist [time=%s] [key=%s(%s)]' % (call_info_t.callid, pkt_time, skinny_key_events[sub_msg.key], sub_msg.key))

        #       self._context.calls[call_info_t.callid] = call_info_t
        #       print 'ADD [0] [time=%s] [key=%s(%s)]' % (pkt_time, skinny_key_events[sub_msg.key], sub_msg.key)

        #       self._context.pending_transfers.append( sub_msg.callid );

        #   # join 2 transfered parties
        #   else:
        #       callid_t = self._context.pending_transfers.pop()
        #       if callid_t != None:                    
        #           call_info_from = self._context.calls[callid_t]
        #           # call_info_t => call_info
        #           call_info_from.transfer_vs = sub_msg.callid
        #           call_info.transfer_vs = callid_t
        #       else:
        #           raise ValueError('no transfer visavi')

        # elif sub_msg.key == SkinnyKeyEvents.RESUME:

        #   if sub_msg.callid in self._context.pending_transfers:
        #       self._context.pending_transfers.remove(sub_msg.callid)
        #       # DROPIT
        #       #print 'escape %s from pending transfers' % sub_msg.callid

        # elif sub_msg.callid != 0 and self._context.calls.has_key(sub_msg.callid):
        #   call_info = self._context.calls[sub_msg.callid]

        #   # TODO
        #   # EndCall may be issued at the same time as CCM notified Phone about 'OnHook' state,
        #   # thus call's parse state can be 'Closed'
        #   if sub_msg.key != SkinnyKeyEvents.END_CALL:
        #       if self.__test_call_info_alive(call_info, msg.msg, False) == False:
        #           #print 'put %s to error, key %s' % (sub_msg.callid, sub_msg.key)
        #           call_info.set_call_error(ErrorType2.OutOfState)

        prior_keys = [
            SkinnyKeyEvents.NewCall,
            SkinnyKeyEvents.Redial,
            SkinnyKeyEvents.CFwdAll
        ]

        # EndCall*, NewCall*, CFwdAll*

        # TODO: finally, it should be:
        # if (sub_msg.callid == 0 and sub_msg.callid in prior_keys) ...

        if sub_msg.key == SkinnyKeyEvents.NewCall or \
            sub_msg.key == SkinnyKeyEvents.Redial or \
            sub_msg.key == SkinnyKeyEvents.CFwdAll:

            if sub_msg.key != SkinnyKeyEvents.NewCall \
                and sub_msg.key != SkinnyKeyEvents.Redial \
                and sub_msg.key != SkinnyKeyEvents.CFwdAll: # FIXME
                self.__assert( sub_msg.callid == 0, 'sub_msg.key: %s' % skinny_key_events[sub_msg.key] )

        elif sub_msg.key < SkinnyKeyEvents.MaxKnown:
            if sub_msg.key != SkinnyKeyEvents.EndCall: # FIXME
                self.__assert( sub_msg.callid != 0, 'sub_msg.key: %s' % skinny_key_events[sub_msg.key] )


        if sub_msg.key < SkinnyKeyEvents.MaxKnown:
            if sub_msg.callid != 0:
                if self._context.calls.has_key(sub_msg.callid):
                    call_info = self._context.calls[sub_msg.callid]

            else:
                if sub_msg.key in prior_keys:
                    self._context.callfree_soft_keys[pkt_time] = sub_msg.key
                else:
                    self._context.set_session_error( ErrorType2.SoftKeyOutOfState )

        # unknown key, may be placed 'in-call' (callid != 0) or out of any call (callid == 0)
        # for now, just log these keys
        else:
            if sub_msg.callid != 0 and self._context.calls.has_key(sub_msg.callid):
                call_info = self._context.calls[sub_msg.callid]

            self._context.set_session_error( ErrorType2.SoftKeyUnknown )

        if call_info != None:
            call_info.keys_history[pkt_time] = SkinnyKeyEvents(sub_msg.key) if sub_msg.key <= SkinnyKeyEvents.MaxKnown else sub_msg.key

            # if sub_msg.key != SkinnyKeyEvents.EndCall:
            #   if call_info.parse_state != ParseState.OPENED:
            #       call_info.set_call_error(ErrorType2.SoftKeyOutOfState)

    
    def __process__0x0004__enbloc_call(self, msg, fdir, pkt_time):
        pass


    def __process__0x0022__open_receive_channel_ack(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageOpenReceiveChannelAck]
        #sub_msg.show()

        if self._context.calls.has_key(sub_msg.callid):             
            call_info = self._context.calls[sub_msg.callid]

            rtp_flow = call_info.get_rtp_flow(sub_msg.passthru)
            rtp_flow.flags |= RtpFlowFlags.LocalConfirmed
            rtp_flow.local = (sub_msg.remote, sub_msg.port)
            rtp_flow.set_st_timestamp(pkt_time)

        if (self._context.derived_info['session_flags'] & SkinnySessionFlags2.RealIpKnown) == 0:
            self._context.derived_info['real_ip'] = sub_msg.remote
            self._context.derived_info['session_flags'] |= SkinnySessionFlags2.RealIpKnown


    def __process__0x0154__start_media_transmission_ack(self, msg, fdir, pkt_time):
        
        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageStartMediaTransmissionAck]
        #sub_msg.show()

        if self._context.calls.has_key(sub_msg.conference):             
            call_info = self._context.calls[sub_msg.conference]

            rtp_flow = call_info.get_rtp_flow(sub_msg.passthru)
            rtp_flow.flags |= RtpFlowFlags.RemoteConfirmed
            rtp_flow.local_orig = (sub_msg.remote, sub_msg.port)
            rtp_flow.set_st_timestamp(pkt_time)


    def __process__0x0023__connection_stat_res(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageConnectionStatisticsRes]
        #sub_msg.show()

        if self._context.calls.has_key(sub_msg.callid):
            call_info = self._context.calls[sub_msg.callid]

            rtp_stats = sub_msg.get_stats()
            call_info.rtp_stats[pkt_time] = rtp_stats


            if rtp_stats['packetsSent'] == 0 and rtp_stats['packetsRecv'] == 0:
                # be carefull here: this may be (false positive) triggered by 0-sec long RTP flow,
                # until now we can't reliable map RTP to ConnectionStatRes messages
                call_info.set_call_error(ErrorType2.RtpNoMedia)

            elif rtp_stats['packetsSent'] == 0:
                call_info.set_call_error(ErrorType2.RtpOneWayMediaNoSend)

            elif rtp_stats['packetsRecv'] == 0:
                call_info.set_call_error(ErrorType2.RtpOneWayMediaNoRecv)


    def __process__0x002A__media_transmission_failure(self, msg, fdir, pkt_time):
        raise ValueError('handle me')

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageMediaTransmissionFailure]
        #sub_msg.show()

        if self._context.calls.has_key(sub_msg.callid):
            call_info = self._context.calls[sub_msg.callid]

            call_info.set_call_error(ErrorType2.RtpMediaFailure)

            # TODO: attach BIT to RtpFlow


    #
    # to Phone, Dir.DIR_REPLY
    #


    def __process__0x0081__register_ack_msg(self, msg, fdir, pkt_time): # TODO: must be turn-of-able

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageRegisterAck]
        #sub_msg.show()

        reg_ack_info = sub_msg.get_register_ack_info()

        if reg_ack_info != None:
            self._context.set_register_ack_info(reg_ack_info)


    def __process__0x0147__line_stat_v2_res(self, msg, fdir, pkt_time): # TODO: must be turn-of-able
        
        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageLineStatV2]
        #sub_msg.show()

        line_info = sub_msg.get_line_info()

        if line_info != None:
            self._context.set_line_info(line_info)


    def __process__0x0111__call_state(self, msg, fdir, pkt_time):

        call_info = None

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageCallState]
        #sub_msg.show()

        self.__assert( sub_msg.callid != 0 )

        # DROPIT
        #print '*** __process__0x0111__call_state : callid = %s' % sub_msg.callid
        ### print '[__process__0x0111__call_state] callid = %s, state = %s' % (sub_msg.callid, sub_msg.state)
        #print 'keys: %s' % self._context.calls.keys()


        if sub_msg.state == SkinnyCallStates.RingIn:

            self._context.test_start_call(sub_msg.callid)

            # TODO: fix ugly way to bypass retransmits

            if self._context.calls.has_key(sub_msg.callid):
                call_info = self._context.calls[sub_msg.callid]
                call_info.set_call_error(ErrorType2.OutOfState)
            else:
                call_info = CallInfo(SkinnyCallType.INBOUND_CALL)
                call_info.line = sub_msg.instance
                call_info.callid = sub_msg.callid

            call_info.update_pstate( ParseState.OPENED, pkt_time )

            self._context.calls[call_info.callid] = call_info
            self._context.begin_call(call_info.callid)


        elif sub_msg.state == SkinnyCallStates.OffHook:

            self._context.test_start_call(sub_msg.callid)

            if self._context.calls.has_key(sub_msg.callid):
                
                call_info = self._context.calls[sub_msg.callid]

                self.__assert( call_info.parse_state != ParseState.CLOSED )
                
                self.__assert( call_info.call_type == SkinnyCallType.INBOUND_CALL or call_info.call_type == SkinnyCallType.FORWARD_CALL )

            else:

                call_info = CallInfo(SkinnyCallType.OUTBOUND_CALL)
                call_info.line = sub_msg.instance
                call_info.callid = sub_msg.callid
                call_info.update_pstate( ParseState.OPENED, pkt_time )

                # assign soft keys placed prior to call to call's keys history
                for time, key in self._context.callfree_soft_keys.items():
                    call_info.keys_history[time] = SkinnyKeyEvents(key) if key <= SkinnyKeyEvents.MaxKnown else key
                self._context.callfree_soft_keys = {}

                self._context.calls[call_info.callid] = call_info
                self._context.begin_call(call_info.callid)


        elif sub_msg.state == SkinnyCallStates.OnHook:

            self._context.test_end_call(sub_msg.callid)


            if self._context.calls.has_key(sub_msg.callid):

                call_info = self._context.calls[sub_msg.callid]

                self.__assert( call_info.parse_state != ParseState.CLOSED )
                
                call_info.update_pstate( ParseState.CLOSED, pkt_time )

                # we mark this call as completed, but it still may accept
                # commands until -next- call ends.
                self._context.complete_call(call_info.callid)

                self._context.classify_call(call_info)

                if self._context.update_line_info(call_info.callid):
                    self._context.complete_session_header()


        else: # Connected, Proceed, RingOut, Hold
            if self._context.calls.has_key(sub_msg.callid):             
                call_info = self._context.calls[sub_msg.callid]

                self.__assert( call_info.parse_state != ParseState.CLOSED )


        self._context.test_append_call_state(sub_msg.callid, sub_msg.state)

        if call_info != None:
            # 2 call state msgs may arrive within same tcp segment
            while call_info.states_history.has_key(pkt_time):
                pkt_time += 0.00001

            call_info.states_history[pkt_time] = SkinnyCallStates(sub_msg.state)

        return 0


    def __process__0x014A__call_info(self, msg, fdir, pkt_time):        

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageCM5CallInfo]
        #sub_msg.show()

        #print '*** __process__0x014A__call_info : callid = %s' % sub_msg.callid

        if self._context.calls.has_key(sub_msg.callid):             
            call_info = self._context.calls[sub_msg.callid]

            #print 'CM5CallInfo : id = %s, pstate = %s' % (sub_msg.callid, call_info.parse_state)
            #print call_info.states_history

            # TODO: print pkt number in exception

            self.__test_call_info_alive(call_info, msg.msg)
            
            state = call_info.get_state()

            if state in call_info.party_info.keys():
                cur_party_info = call_info.party_info[state]
                new_party_info = sub_msg.get_party_info(msg.res, 'windows-1252')

                if new_party_info != cur_party_info:
                    call_info.party_info[state] = new_party_info

            if call_info.call_type == SkinnyCallType.INBOUND_CALL and sub_msg.calltype == SkinnyCallType.FORWARD_CALL:
                call_info.call_type = SkinnyCallType.FORWARD_CALL
            
        # TODO: add to in-the-middle CallId/PPID @ PhoneSession
        # else:
        #   raise ValueError('callid %s not found for CallInfo msg' % sub_msg.callid)


    def __process__0x011D__dialed_number(self, msg, fdir, pkt_time):
        pass


    def __process__0x0105__open_receive_channel(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageOpenReceiveChannel]
        #sub_msg.show()

        if self._context.calls.has_key(sub_msg.conference):             
            call_info = self._context.calls[sub_msg.conference]

            rtp_flow = call_info.get_rtp_flow(sub_msg.passthru)
            rtp_flow.flags |= RtpFlowFlags.Local
            rtp_flow.remote_orig = (sub_msg.remote, sub_msg.remotePortNumber)
            rtp_flow.set_st_timestamp(pkt_time)
            rtp_flow.local_rate = sub_msg.rate # recv rate


    def __process__0x008A__start_media_transmission(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageStartMediaTransmission]
        #sub_msg.show()

        if self._context.calls.has_key(sub_msg.conference):             
            call_info = self._context.calls[sub_msg.conference]

            rtp_flow = call_info.get_rtp_flow(sub_msg.passthru)
            rtp_flow.flags |= RtpFlowFlags.Remote
            rtp_flow.remote = (sub_msg.remote, sub_msg.port)
            rtp_flow.set_st_timestamp(pkt_time)
            rtp_flow.remote_rate = sub_msg.rate # send rate


    def __process__0x0106__close_receive_channel(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageCloseReceiveChannel]
        #sub_msg.show()

        if self._context.calls.has_key(sub_msg.conference):             
            call_info = self._context.calls[sub_msg.conference]

            rtp_flow = call_info.get_rtp_flow(sub_msg.passthru, False)
            if rtp_flow:
                rtp_flow.flags |= RtpFlowFlags.LocalClosed
                rtp_flow.set_end_timestamp(pkt_time)


    def __process__0x008B__stop_media_transmission(self, msg, fdir, pkt_time):

        self._test_no_raw_layer(msg)

        sub_msg = msg[SkinnyMessageStopMediaTransmission]
        #sub_msg.show()

        if self._context.calls.has_key(sub_msg.conference):             
            call_info = self._context.calls[sub_msg.conference]

            rtp_flow = call_info.get_rtp_flow(sub_msg.passthru, False)
            if rtp_flow:
                rtp_flow.flags |= RtpFlowFlags.RemoteClosed
                rtp_flow.set_end_timestamp(pkt_time)


    def __process__0x0107__connection_stat_req(self, msg, fdir, pkt_time):
        pass


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


