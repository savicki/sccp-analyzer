
import re, json

from call_info import *
from phone_session import PhoneSession, PhoneSessionIterator
from mtp_session import MTPSession, MTPSessionIterator, RelayPoint


_JSON_CLASSES = {
    'CallInfo'      : CallInfo, 
    'RtpFlow'       : RtpFlow,
    'RelayPoint'    : RelayPoint,
    'PhoneSession'  : PhoneSession,
    'MTPSession'    : MTPSession
}

# single-value (!) enums
_JSON_ENUMS = {
    'SkinnyCallStates'  : SkinnyCallStates,
    'SkinnyCallType'    : SkinnyCallType,
    'ParseState'        : ParseState,
    'SkinnyKeyEvents'   : SkinnyKeyEvents
}


def str_with_fatfloat(x):
    return str(x) if type(x) != float else str('%.20g' % x)


def _str2enum(arg):
    ### print "_str2enum ", type(arg) == unicode, arg
    if type(arg) == unicode:
        dot_ind = arg.find('.')
        if dot_ind > 0: 
            m = re.match(r'^(?:[a-zA-Z\d_]+?)\.(?:[a-zA-Z_]+)$', arg) # reject IP adrresses
            if m:
                type_name = arg[:dot_ind]
                type_value = arg[dot_ind+1:]
                
                if type_name in _JSON_ENUMS.keys(): # reject e.g. "Matelskaya.Yul"
                    ### print "_str2enum     ", type_name, type_value
                    return getattr(_JSON_ENUMS[type_name], type_value)

    return arg


def _enum2str(v):
    ### print "_enum2str: ", v, type(v)
    
    # stringify single-value (!) enums
    if type(v) in _JSON_ENUMS.values():
        return str(v)
    
    return v


def _convert_keys(obj, convert_key=str, convert_val = None):

    if isinstance(obj, list):
        return [_convert_keys(i, convert_key, convert_val) for i in obj]
    
    if not isinstance(obj, dict):
        return convert_val(obj) if convert_val else obj

    return {convert_key(k): _convert_keys(v, convert_key, convert_val) for k, v in obj.items()}


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class SkinnySessionsJsonEncoder(json.JSONEncoder):
    def default(self, obj):
        ### print "*** default ***", type(obj), type(obj) in _JSON_CLASSES.values()

        if type(obj) in _JSON_CLASSES.values():
            return {
                "_type": obj.__class__.__name__, 
                # "value": _convert_keys(get_public_fields(obj.__dict__), convert_val=_enum2str)
                "value": _convert_keys(obj.get_json_dict(), convert_key=str_with_fatfloat, convert_val=_enum2str)
            }

        return super(SkinnySessionsJsonEncoder, self).default(obj)


class SkinnySessionsJsonDecoder(json.JSONDecoder):
    def __init__(self, *args, **kwargs):
        json.JSONDecoder.__init__(self, object_hook=self.object_hook, *args, **kwargs)

    def object_hook(self, obj):
        ### print "object_hook", obj, "\n"

        if '_type' not in obj:
            return obj
        cls_type_s = obj['_type']
        
        if cls_type_s in _JSON_CLASSES.keys():
            cls_type = _JSON_CLASSES[cls_type_s]
            ### print cls_type
            ### print obj['value']
            return cls_type(data=_convert_keys(obj['value'], convert_key=_str2enum, convert_val=_str2enum))

        return obj