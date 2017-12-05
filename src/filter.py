
import os, sys, re, argparse
from scapy.all import *
from scapy.contrib.skinny import *

from common_types import *
from call_info import *
from phone_session import PhoneSession, PhoneSessionIterator
from mtp_session import MTPSession, MTPSessionIterator, RelayPoint
from json_serialization import SkinnySessionsJsonEncoder, SkinnySessionsJsonDecoder


class Type(object):
    _ops = []
    _arg_ops = {}
    _str_type = ''


    def __init__(self, field):
        self._field = field
        self._base_type = None # always 'None' for ordinal types

    def get_field(self):
        return self._field

    def get_base_type(self):
        return type(self._base_type)

    def validate_operator(self, op):                ### 1-st step
        return op in self._ops

    def validate_agr_operator(self, agr_op):
        # print type(self), self._arg_ops.keys()
        if agr_op in self._arg_ops.keys():
            agr_op_info = self._arg_ops[agr_op]
            
            agr_type = agr_op_info[0]
            agr_fmt = agr_op_info[1][self.get_base_type()]
            
            return agr_type( agr_fmt % self.get_field() )

        return self

    # return '%s %s %s' % (field, op, value)        ### 3-rd step  

    def validate_value(self, value_str):            ### 2-nd step     
       return False, value_str, None

    def compose_expr(self, field, operator, value, validate_opaque):
        
        expr = '%s %s %s' % (field, operator, value)

        return expr

    def type2str(self):
        if self._base_type:
            return '%s(%s)' % (self._str_type, self._base_type._str_type)
        else:
            return self._str_type


class Num(Type):
    _ops = ['==', '!=', '>', '<', '>=', '<=', '&']
    _str_type = 'num'

    def __init__(self, exp):
        Type.__init__(self, exp)

    # accepted types: int, float, IntEnum
    def validate_value(self, value_str):
        # print 'Num::validate_value ',  value_str
        m = None
        value_ret = None
        int_base = None # default for enums

        while True:
            # int (hex or dec) or float
            m = re.match(r'^(?:(?:(?P<hex>0x)?(?(hex)[\da-fA-F]+|\d+))|(?:\d+\.\d+))$', value_str)
            if m: 
                value_ret = value_str
                int_base = 16 if m.group('hex') else 10
                break
            
            # IntEnum
            m = re.match(r'^(?P<enum_type>[a-zA-Z\d_]+?)\.(?P<enum_value>[a-zA-Z_\d_]+)$', value_str)
            if m:
                type_name = m.group('enum_type')
                type_value = m.group('enum_value')
                # print type_name, type_value

                value_ret = getattr(eval(type_name), type_value)
                if not isinstance(value_ret, int):
                    m = None
                    break
            
            break

        return m != None, int(value_ret, int_base) if int_base else int(value_ret) if m else value_str, None


class BitNum(Num):
    _str_type = 'bit num'
    pass


class Str(Type):
    _ops = ['contains', '==', '!=']
    _str_type = 'string'

    def __init__(self, exp):
        Type.__init__(self, exp)
    
    # accepted types: str
    def validate_value(self, value_str):
        # print 'Str::validate_value ',  value_str
        
        m = re.match(r'^(?P<left_q>[\'\"]?)(?P<value>[^\'\"]+)(?(left_q)(?:[\'\"])|$)$', value_str)
        ## print m.group('value') # V-2
        return m != None, '%s' % m.group('value') if m else value_str, None

    def compose_expr(self, field, operator, value, validate_opaque):
        if operator != 'contains':
            expr = '%s %s "%s"' % (field, operator, value)

        else:
            expr = '%s.find("%s") >= 0' % (field, value)

        return expr


class Array(Type):
    _ops = ['has']
    _arg_ops = {
        'len': (Num, {
            Num : 'len(%s)',
            BitNum : 'len([bit for bit in range(0, 32) if ((1 << bit) & %s) != 0])',
            Str : 'len(%s)'
        })
    }
    _str_type = 'array'

    def __init__(self, base_type):
        Type.__init__(self, "<no field for containers>")
        self._base_type = base_type

    # accepted types: str
    def validate_value(self, value_str):
        is_conjuct = True

        if value_str.find(',') != -1:
            value_arr = value_str.split(',')
            is_conjuct = False
        elif value_str.find('+') != -1:
            value_arr = value_str.split('+')
        else:
            value_arr = [value_str]

        value_arr = [i.strip() for i in value_arr]
        value_arr_vld = []

        for value in value_arr:
            validate_res = self._base_type.validate_value(value)
            if not validate_res[0]:
                return False, [], None
            value_arr_vld.append( validate_res[1] )
              
        # test /"[\w\W]?"/ regex
        # print 'Array:validate_value: %s, %s' % (value_arr, type(self._base_type))

        # AndArray/OrArray x Int/Bit/Str + operator

        # Bit:
        #   AndArray/OrArray    : ordinal_value
        #   .len                : len(bits)
        # Str, Int:
        #   AndArray/OrArray : array
        #   .len                : len(array)

        res_value = None
        if isinstance(self._base_type, BitNum):
            res_value = reduce( lambda x, y : x | y, value_arr_vld )

        elif isinstance(self._base_type, Num):
            res_value = value_arr_vld
        
        elif isinstance(self._base_type, Str):
            res_value = [i.lower() for i in value_arr_vld]

        # 'has' for bits : 
        return True if res_value else False, res_value, is_conjuct

    def compose_expr(self, field, operator, value, validate_opaque):
        is_conjuct = validate_opaque
        
        operator = '==' if is_conjuct else '>'

        if isinstance(self._base_type, BitNum):
            # (@searchee & @bit_field)
            left_expr = '(%s & %s)' % (field, value)
            # @searchee / 0
            right_expr = '%s' % value if is_conjuct else '0' 

        elif isinstance(self._base_type, Num):
            # len( [i for i in @searchee if i in @int_array_field] )
            left_expr = 'len([i for i in %s if i in %s])' % (field, value)
            # len( @searchee ) / 0
            right_expr = ('len(%s)' % value) if is_conjuct else '0' 

        elif isinstance(self._base_type, Str):
            # len( [s for s in @searchee if len( [i for i in @str_array_field if i.find(s) != -1 ] ) > 0] )
            left_expr = 'len([s for s in %s if len( [i for i in %s if i.lower().find(s) != -1 ] ) > 0])' % (value, field)
            # len( @searchee ) / 0
            right_expr = ('len(%s)' % value) if is_conjuct else '0' 

        expr = '%s %s %s' % (left_expr, operator, right_expr)

        return expr

    def get_field(self):
        return self._base_type.get_field()


_fields_mapper = {
    'session': {
        'owner' : {
            'protocol' : {
                'used'          : Num('session.register_info["protocol"]["used"]'),
                'max_supported' : Num('session.register_info["protocol"]["max_supported"]'),
                'requested'     : Num('session.register_info["protocol"]["requested"]'),
            },
            'names' :       Array( Str('session.register_info["name"].values()') ),
            'numbers' :     Array( Str('session.register_info["number"].values()') )
        },
        'summary': {
            'soft_keys'     : Array( Num('session.calls_summary["soft_keys"]') ),
            'call_types'    : Array( Num('session.calls_summary["call_types"]') ),
            'call_errors'   : Array( BitNum('session.session_errors') ),
            'call_attrs'    : Array( BitNum('session.calls_summary["call_attrs"]') ),
            'call_states'   : Array( Num('session.calls_summary["call_states"]') )
        },
        'info' : {
            'filename' :    Str('session.s_info.filename'),
            'time' : {
                'start' :   Num('session.s_info.st_time'),
                'end' :     Num('session.s_info.end_time')
            },
            'middle' :      Num('session.s_info.in_mdl')
        }
    },
    'call': {
        'callid'            : Num('call.callid'),
        'type'              : Num('call.call_type'),
        'states'            : Array( Num('call.states_history.values()') ),
        'errors'            : Array( BitNum('call.call_errors') ),
        'attrs'             : Array( BitNum('call.call_attrs') ),
        'soft_keys'         : Array( Num('call.keys_history.values()') ),

        'callee' : {
            'number' :      Str( 'call.get_party_end("remote")[0]' ),
            'name' :        Str( 'call.get_party_end("remote")[1]' )
        },
        'caller' : {
            'number' :      Str( 'call.get_party_end("local")[0]' ),
            'name' :        Str( 'call.get_party_end("local")[1]' )
        },

        'rtp' : {
            'flows'         : Array( Num('call.rtp_flows.keys()') ),
            'flows_oneway'  : Array( Num('call.rtp_flows_oneway.keys()') ),
            'flows_duplex'  : Array( Num('call.rtp_flows_twoway.keys()') ),
            'flows_error'   : Array( Num('call.rtp_flows_unknown.keys()') ),
            'stats'         : Array( Num('call.rtp_stats.keys()') ),
            'dur_min'       : Num('call.rtp_durations[0]'),
            'dur_max'       : Num('call.rtp_durations[1]')
        },
        
        'time' : {
            'start'         : Num('call["st_time"]'),
            'end'           : Num('call["end_time"]'),
            'duration'      : Num('call.get_duration_sec()')
        }
    },
    'endpoint' : {
        'sessions' :        Array( Num('endpoint.sessions') ),
        'channels' :        Array( Num('endpoint.channels') ),
        'falls' : {
            'items' :       Array( Num('endpoint.falls') ),
            'intervals' : {
                'min' :     Num('endpoint.stats["duration"]["min"]'),
                'max' :     Num('endpoint.stats["duration"]["max"]')
            }
        },
        # FIXME: [almost] copy paste from 'session.owner' path
        'owner' : {
            'protocol' : {
                'used'          : Num('endpoint.owner["protocol"]["used"]'),
                'max_supported' : Num('endpoint.owner["protocol"]["max_supported"]'),
                'requested'     : Num('endpoint.owner["protocol"]["requested"]'),
            },
            'names'         : Array( Str('endpoint.owner["name"].values()') ),
            'numbers'       : Array( Str('endpoint.owner["number"].values()') )
        },
    },
    'fall' : {
        'duration' :        Num('fall.duration'),
        'last_call' : {
            # FIXME: [almost] copy paste from 'call' path
            'duration' :    Num('( fall.last_call.get_duration_sec() if fall.last_call else 0 )'),
            'ends' :        Num('( (fall.last_call.get_owner().s_info.end_time - fall.last_call.end_time) if fall.last_call else 0 )'),
            'visavi' : {
                'number' :  Str('( fall.last_call.get_party_end("local")[0] if fall.last_call else "" )'),
                'name' :    Str('( fall.last_call.get_party_end("local")[1] if fall.last_call else "" )')
            }
        },
        'next_call' : {
            'duration' :    Num('( fall.next_call.get_duration_sec() if fall.next_call else 0 )'),
            'starts' :      Num('( (fall.next_call.st_time - fall.next_call.get_owner().s_info.st_time) if fall.next_call else 0 )'),
            'visavi' : {
                'number' :  Str('( fall.next_call.get_party_end("local")[0] if fall.next_call else "" )'),
                'name' :    Str('( fall.next_call.get_party_end("local")[1] if fall.next_call else "" )')
            }
        }
    }
}

"""
    [1,2,3,4,5,6,7,8,9] has 1 + 99 : 

    int array:
      '[1,2,3,4] has 1+2'
      AND: len( [i for i in @searchee if i in @int_array_field] ) == len( @searchee )
      OR:  len( [i for i in @searchee if i in @int_array_field] ) > 0

    bit array:
      '0xF0 has 1+2'
      AND: ( @searchee & @bit_field ) == @searchee
      '0xF0 has 1, 2'
      OR:  ( @searchee & @bit_field ) > 0
      
    str array:
      ['andy','john'] has ['and', 'jo']
      AND: len( [s for s in @searchee if len( [i for i in @str_array_field if i.find(s) != -1 ] ) > 0] ) == len( @searchee )
      AND: len( [s for s in @searchee if len( [i for i in @str_array_field if i.find(s) != -1 ] ) > 0] ) > 0

    Array(int, 'session.summary.call_types')      vs AndArray/OrArray
    Array(bit, 'session.analysis.sccp_errors')    vs AndArray/OrArray
    Array(str, 'session.owner.names')             vs AndArray/OrArray
"""

def _convert_field(scope, fields):
    subquery = scope
    next_map = _fields_mapper[scope]

    while len(fields) > 0:
        field = fields[0]
        fields = fields[1:]
        ### print "\n", field, next_map, "\n"

        subquery += '.' + field
        next_map = next_map[field] if next_map.has_key(field) else None
        if not next_map:
            raise ValueError('subquery \'%s\' not implemented' % subquery)

    if not isinstance(next_map, Type):
        raise ValueError('\'%s\' is not completed' % subquery)

    # print '\'%s\' => \'%s\'' % (subquery, next_map.get_field())
    return next_map


def _walk_fields_mapper_keys(str_res, obj, padding = ''):
    if isinstance(obj, dict):
        str_res += '\n'

        for k in sorted(obj.keys()):
            str_res +=  '%s %s' % (padding, k)
            str_res = _walk_fields_mapper_keys(str_res, obj[k], padding + '   ')
    
    elif isinstance(obj, Type):
        str_res += ' : %s\n' % obj.type2str()

    return str_res

def stringify_filter_map():
    str_res = _walk_fields_mapper_keys('', _fields_mapper)
    return str_res


def parse_single_expression(filter_str, scope, strict_scope = True):
    # print 'filter_str: \'%s\'' % filter_str

    parts = [i for i in filter_str.split(' ') if i]
    
    # print parts
    if len(parts) < 3:
        raise ValueError('too short query \'%s\'' % filter_str)

    field_str = parts[0]
    m = re.match(r'^(?P<scope>session|call|endpoint|fall)(?P<fields>(?:\.\w+)*)(?P<dot>\.)(?(dot)(?P<last_field>\w+)|$)$', field_str)
    if not m:
        raise ValueError('wrong field name \'%s\'' % field_str)
    scope_used = m.group('scope')
    if scope_used != scope:
        if strict_scope:
            raise ValueError('expected \'%s\' scope, but \'%s\' given' % (scope, scope_used))
        else:
            return 'True', True # dummy expr

    fields = [ i for i in m.group('fields').split('.') if i]
    field_op = m.group('last_field')

    if field_op not in ['len']:
        fields.append(field_op)
        field_op = None

    # print scope, fields, field_op
    field_type = _convert_field(scope_used, fields)

    if field_op:
        field_type = field_type.validate_agr_operator(field_op)
        if not field_type:
            raise ValueError('wrong last property name \'%s\'' % field_op)

    op_str = parts[1]
    op_res = field_type.validate_operator(op_str)
    if not op_res:
        raise ValueError('not acceptable operator \'%s\' for this field' % op_str)

    value_str = ' '.join(parts[2:])
    value_res = field_type.validate_value(value_str)
    if not value_res[0]:
        raise ValueError('wrong value \'%s\'' % value_str)

    expr = field_type.compose_expr( field_type.get_field(), op_str, value_res[1], value_res[2] )

    # 'session.owner.protocol.used' => session["owner"]["protocol"]["used"]
    return '%s' % expr, False


def parse_expression(filter_str, scope, parse_fn = parse_single_expression, strict_scope = True):
    subst_map = {
        '&&' : 'and',
        '||' : 'or',
        '!(' : 'not (',
    }
    for search, replace in subst_map.items():
        filter_str = filter_str.replace(search, replace)

    i, str_len = 0, len(filter_str)

    expr_arr = []
    st_ind = -1
    last_c_ind = -1
    o_gr, c_gr = 0, 0
    non_expr_st_ind = 0

    while i < str_len:
        if filter_str[i] == '(':
            o_gr += 1
            st_ind = i
            if last_c_ind >= 0 and i - last_c_ind < 3:
                raise ValueError('missed \'||\' or \'&&\' between expressions @ %s..%s' % (last_c_ind, i))

        elif filter_str[i] == ')':
            c_gr += 1
            if st_ind != -1:
                non_expr = filter_str[non_expr_st_ind:st_ind + 1] # include '('
                non_expr_st_ind = i # include ')'
                expr_arr.append( (non_expr, False) )

                expr = filter_str[st_ind+1:i]

                m = re.match(r'^([\w\W]*?)(?:\|\||\&\&)([\w\W]*?)$', expr)
                ### print expr, m
                if not m:
                    #expr_arr.append( (expr, st_ind + 1, len(expr)) )
                    expr_arr.append( (expr, True) )
                else:
                    raise ValueError('expression \'%s\' must not contain \'||\' or \'&&\'' % expr)

                st_ind = -1

            elif c_gr > o_gr:
                raise ValueError('closing not opened group')

            last_c_ind = i

        i += 1

    non_expr = filter_str[non_expr_st_ind:str_len]
    expr_arr.append( (non_expr, len(expr_arr) == 0) )

    if o_gr != c_gr:
        raise ValueError('mismatch \'(\' and \')\' count (%s vs %s), check you expresion' % (o_gr, c_gr))

    filter_str_ret = ''
    dummy_all = True

    for expr in expr_arr:
        if expr[1]:
            expr_inj, dummy_expr = parse_fn(expr[0], scope, strict_scope = strict_scope)
            dummy_all &= dummy_expr
        else:
            expr_inj = expr[0]

        filter_str_ret += expr_inj

        ### print '\n\'%s\' ==> \'%s\'\n' % (expr[0], expr_inj)

    # print filter_str_ret # V-1
    return filter_str_ret, dummy_all


parser = argparse.ArgumentParser()
parser.add_argument('-scp', '--scope', help='filter string', required=True)
parser.add_argument('-s-query', '--single-filter', help='filter string', required=False)
parser.add_argument('-query', '--filter', help='filter string', required=False)


if __name__ == "__main__":

    args = parser.parse_args()

    if args.single_filter:
        print parse_single_expression(args.single_filter, args.scope.lower())

    elif args.filter:
        print parse_expression(args.filter, args.scope.lower())

