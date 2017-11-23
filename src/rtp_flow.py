
from enum import *

from common_types import BitEnum, JsonSerializable, Ownable


class RtpFlowFlags(BitEnum):
    No              = 0
    Local           = 1 << 0 # local IP:port, from ORCA
    LocalConfirmed  = 1 << 1 
    LocalClosed     = 1 << 2
    Remote          = 1 << 3 # remote IP:port, from SMT
    RemoteConfirmed = 1 << 4
    RemoteClosed    = 1 << 5
    RemoteFailure   = 1 << 6


# ORC   --> create_flow + init @to_local
# ORCA  --> to_local_confirmed  + learn local real. IP of flow
# SMT   --> create_flow + init @to_remote
# SMTa  --> to_remote_confirmed + learn remote real. IP of flow
# SMTf  --> to_remote_fail

# TODO: handle MediaTransmissionFailure
class RtpFlow(JsonSerializable, Ownable):
    def __init__(self, ppid = 0, data = None):
        Ownable.__init__(self)

        if data:
            self.__dict__ = data
        else:
            self.ppid = ppid
            self.flags = RtpFlowFlags.No
            self.local = None # from ORCa
            self.remote = None # from SMT
            self.local_orig = None # from SMTa
            self.remote_orig = None # from ORC
            self.st_time = None
            self.end_time = None


    def __str__(self):
        return "[%s] %s:%s --> %s:%s" % (
            self.ppid, 
            self.local[0] if self.local else "", 
            self.local[1] if self.local else "", 
            self.remote[0] if self.remote else "", 
            self.remote[1] if self.remote else "")


    # def is_completed(self):
    #   res = True
    #   if self.local:
    #       res = res and self.flags and (RtpFlowFlags.Local | )

    def is_one_way(self):
        return (self.local != None) ^ (self.remote != None)

    def is_two_way(self):
        return (self.local != None) and (self.remote != None)

    def get_key(self):
        return '%s:%s - %s:%s' % (self.local[0], self.local[1], self.remote[0], self.remote[1])

    def get_inv_key(self):
        return '%s:%s - %s:%s' % (self.remote[0], self.remote[1], self.local[0], self.local[1])
