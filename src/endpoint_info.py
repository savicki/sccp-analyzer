
from enum import *
import json

from common_types import SkinnySessionFlags, SessionBase, SessionIterator, SessionHandler, JsonSerializable, RtpFlowsContainer, ErrorType2
from field_classifier import *
from call_info import *


class EndpointInfo(object):
    def __init__(self, owner):
        self.owner = owner
        self.sessions = []
        self.falls = []


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


