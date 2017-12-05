
from enum import *
import json, datetime

from common_types import SkinnySessionFlags, SessionBase, SessionIterator, SessionHandler, JsonSerializable, RtpFlowsContainer, ErrorType2
from field_classifier import *
from call_info import *


class EndpointInfo(object):
    def __init__(self, owner):
        self.owner = owner
        # {local_ip, remote_ip, remote_port} => (session start ind, len)
        self.channels = {}
        self.sessions = []
        self.falls = []
        self.stats = {
            'duration' : {
                'min' : 0,
                'max' : 0
            }
        }


    def add_session(self, new_session):
        channel_key = '%s - %s:%s' % (
            new_session.ip_info.local_ip,
            new_session.ip_info.remote_ip, 
            new_session.ip_info.remote_port
        )

        if not self.channels.has_key(channel_key):
            self.channels[channel_key] = (len(self.sessions), 0) # start ind, len

        channel_info = self.channels[channel_key]
        channel_ind = channel_info[0]
        channel_len = channel_info[1]
        
        ind = 0
        for session in self.sessions[channel_ind:channel_ind+channel_len]:
            if new_session.s_info.end_time < session.s_info.st_time:
                break
            ind += 1

        self.sessions.insert(channel_ind + ind, new_session)
        self.channels[channel_key] = ( channel_info[0], channel_info[1] + 1 )

        # shift upper indexes
        for chkey, chinfo in self.channels.items():
            if chkey != channel_key and chinfo[0] > channel_ind:
                self.channels[chkey] = ( self.channels[chkey][0] + 1, self.channels[chkey][1] )


    def post_process(self):
        #
        # (1) check channels reference integrity
        #
        tries = 0
        ind = 0
        st_ind = 0
        expected_count = 0

        while tries < len(self.channels.values()):
            tries += 1
            for ch_info in self.channels.values():
                if ch_info[0] == st_ind:
                    st_ind += ch_info[1]
                
            if st_ind == len(self.sessions):
                break

        if st_ind != len(self.sessions):
            raise ValueError('failed to check channels reference integrity')


        for chkey, chinfo in self.channels.items():
            count = chinfo[1]
            if count < 2:
                continue

            expected_count += count - 1

            #print chkey, count

            #
            # (2) create  falls
            #
            st_ind = chinfo[0]

            for session in self.sessions[st_ind:st_ind+count]:
                if count == 1:
                    break
                st_ind += 1 # next session
                count -= 1 # num of pairs
                next_session = self.sessions[st_ind]

                if not (session.s_info.end_time < next_session.s_info.st_time):                    
                    raise ValueError('wrong session (%s) order: [%s,%s] < [%s,%s]' % (
                        self.owner['name']['1'],

                        session.s_info.st_time, 
                        session.s_info.end_time, 

                        next_session.s_info.st_time,
                        next_session.s_info.end_time
                    ))

                fall = FallInfo(chkey, session, next_session)
                self.falls.append(fall)

                if fall.duration > self.stats['duration']['max']:
                    self.stats['duration']['max'] = fall.duration

                if self.stats['duration']['min'] == 0 or fall.duration < self.stats['duration']['min']:
                    self.stats['duration']['min'] = fall.duration
        
        if expected_count != len(self.falls):
            raise ValueError('expectation on falls count failed')

        if len(self.sessions) - len(self.channels) >= 1 and not len(self.channels) > 0:
            raise ValueError('estimated expectations on falls count failed')


    def show_endpoint_info(self, show_falls = True):
        print '\n[ %s #%s ] %s sessions / %s channels / %s falls' % (
            self.owner['name']['1'], self.owner['number']['1'], 
            len(self.sessions), 
            len(self.channels),
            len(self.falls)
        )

        #
        # print channels
        #
        for chkey in self.channels.keys():
            chinfo = self.channels[chkey]
            print '[ channel: %s ] [ %s session(s) ]' % (chkey, chinfo[1])

            if show_falls:
                for fall in self.falls:
                    if fall.chkey == chkey:
                        print fall

        # print '[ falls ] min: %.2f sec, max: %.2f sec' % (self.stats['duration']['min'], self.stats['duration']['max'])


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class FallInfo(object):
    def __init__(self, chkey, prev, next):
        self.chkey = chkey
        self.prev = prev
        self.next = next
        self.duration = next.s_info.st_time - prev.s_info.end_time

        self.last_call = prev.get_last_call()
        self.next_call = next.get_first_call()


    def show_fall_details(self):
        print self

    def __str__(self):
        if self.last_call or self.next_call:
            return '  [ %.2f sec ] %s] -- [%s \n    last callid: %s, %.2f sec long, then session ends after %.2f sec\n      %s\n    next callid: %s, %.2f sec long, %.2f sec after session begin\n      %s' % (
                self.duration,
                datetime.datetime.fromtimestamp(self.prev.s_info.end_time),
                datetime.datetime.fromtimestamp(self.next.s_info.st_time),

                self.last_call.callid if self.last_call else 0,
                self.last_call.get_duration_sec() if self.last_call else 0,
                (self.last_call.get_owner().s_info.end_time - self.last_call.end_time) if self.last_call else 0,

                self.last_call.get_call_details_oneline() if self.last_call else '',

                self.next_call.callid if self.next_call else 0,
                self.next_call.get_duration_sec() if self.next_call else 0,
                (self.next_call.st_time - self.next_call.get_owner().s_info.st_time) if self.next_call else 0,

                self.next_call.get_call_details_oneline() if self.next_call else ''
            )
        else:
            return '  [ %.2f sec ] %s] -- [%s ' % (
                self.duration,
                datetime.datetime.fromtimestamp(self.prev.s_info.end_time),
                datetime.datetime.fromtimestamp(self.next.s_info.st_time)
            )