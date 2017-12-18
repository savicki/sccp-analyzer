
from enum import *
import datetime

from common_types import BitEnum, JsonSerializable, Ownable


class RtpFlowFlags(BitEnum):
    No              = 0
    Local           = 1 << 0 # ORC  : remote_orig IP:port
    LocalConfirmed  = 1 << 1 # ORCa : local IP:port, recv rate
    LocalClosed     = 1 << 2 # ClRC : nothing
    Remote          = 1 << 3 # SMT  : remote IP:port, send rate
    RemoteConfirmed = 1 << 4 # SMTa : local_orig IP:port, no available for MTP sessions
    RemoteClosed    = 1 << 5 # StopMT : nothing
    RemoteFailure   = 1 << 6 # MediaTransmissionFailure

    # derived (post analyze) flags
    OneWayMediaSetup = 1 << 7
    Closed          = 1 << 8


class RtpFlow(JsonSerializable, Ownable):
    TIME_DELTA_SEC = 10

    def __init__(self, ppid = 0, data = None):
        Ownable.__init__(self)

        if data:
            self.__dict__ = data
        else:
            self.ppid = ppid
            self.flags = RtpFlowFlags.No

            self.local = None # from ORCa
            self.local_orig = None # from SMTa
            self.local_rate = 0 # send rate, from SMT

            self.remote = None # from SMT
            self.remote_orig = None # from ORC
            self.remote_rate = 0 # recv rate, from ORC
            
            self.st_time = None # from ORC/SMT
            self.end_time = None # from CRC/StopMT


    def set_st_timestamp(self, tmstamp):
        if not self.st_time:
            self.st_time = tmstamp

        elif (datetime.datetime.fromtimestamp(tmstamp) - datetime.datetime.fromtimestamp(self.st_time)).total_seconds() > RtpFlow.TIME_DELTA_SEC:
            raise ValueError('exceed TIME_DELTA_SEC')


    def set_end_timestamp(self, tmstamp):
        if not self.end_time:
            self.end_time = tmstamp
            self.flags |= RtpFlowFlags.Closed

        elif (datetime.datetime.fromtimestamp(tmstamp) - datetime.datetime.fromtimestamp(self.end_time)).total_seconds() > RtpFlow.TIME_DELTA_SEC:
            raise ValueError('exceed TIME_DELTA_SEC')


    def __str__(self):
        is_closed = (self.flags & RtpFlowFlags.Closed) != 0
        ### print '   ', self.ppid, is_closed

        st_time_ts = datetime.datetime.fromtimestamp(self.st_time)
        end_time_ts = datetime.datetime.fromtimestamp(self.end_time) if is_closed else None

        return '[%s] [%s - %s] [r:%s ms/p, s:%s ms/p] [%.2f sec] %s:%s --> %s:%s %s' % (
            self.ppid,
            st_time_ts.strftime('%H:%M:%S:%f'), 
            end_time_ts.strftime('%H:%M:%S:%f') if end_time_ts else '???',
            self.local_rate,
            self.remote_rate,
            (end_time_ts - st_time_ts).total_seconds() if end_time_ts else 0.0,

            self.local[0] if self.local else '', 
            self.local[1] if self.local else '', 
            self.remote[0] if self.remote else '', 
            self.remote[1] if self.remote else '', 
            'FAILURE' if (self.flags & RtpFlowFlags.RemoteFailure) != 0 else ''
        )

    def get_duration_sec(self):
        if (self.flags & RtpFlowFlags.Closed) != 0:
            return (datetime.datetime.fromtimestamp(self.end_time) - datetime.datetime.fromtimestamp(self.st_time)).total_seconds()
        else:
            return None

    def is_one_way(self):
        # return (self.local != None) ^ (self.remote != None)
        mask = RtpFlowFlags.LocalConfirmed | RtpFlowFlags.Remote
        return ((self.flags & mask) != 0) and ((self.flags & mask) != mask)

    def is_two_way(self):
        # return (self.local != None) and (self.remote != None)
        mask = RtpFlowFlags.LocalConfirmed | RtpFlowFlags.Remote
        return (self.flags & mask) == mask

    def analyze(self):
        if self.is_one_way():
            self.flags |= RtpFlowFlags.OneWayMediaSetup
        return self.flags

    def get_key(self):
        return '%s:%s - %s:%s' % (self.local[0], self.local[1], self.remote[0], self.remote[1])

    def get_inv_key(self):
        return '%s:%s - %s:%s' % (self.remote[0], self.remote[1], self.local[0], self.local[1])
