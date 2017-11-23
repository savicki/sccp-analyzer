from enum import *

from field_classifier import *


class FieldType(IntEnum):
	NotSet = 0
	Single = 1
	Array = 2


class TypelessField(object):
	def __init__(self):
		self._name = None
		self._type = FieldType.NotSet
		self._value = None

	def _set_name(self, field_name):
		self._name = field_name

	def get_name(self):
		return self._name

	def set_value_from(self, obj_instance):
		self._value = getattr(obj_instance, self._name)
		### print "[TypelessField::set_value_from] name = '%s', value = '%s'" % (self._name, self._value)


class SingleField(TypelessField):
	def __init__(self, field_name):
		self._set_name(field_name)
		self._type = FieldType.Single

	def contains_value(self, expected_value):
		return expected_value == self._value


class ArrayField(TypelessField):
	def __init__(self, field_name):
		self._set_name(field_name)
		self._type = FieldType.Array

	def contains_value(self, expected_value):
		return expected_value in self._value


class DictValuesField(TypelessField):
	def __init__(self, field_name):
		self._set_name(field_name)
		self._type = FieldType.Array

	def contains_value(self, expected_value):
		return expected_value in self._value
	
	def set_value_from(self, obj_instance):
		super(DictValuesField, self).set_value_from(obj_instance)
		self._value = self._value.values()


# # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # # #


class FieldClassifier(object):
	def __init__(self, classify_map):
		self.__classify_map = classify_map

	def __clarify_attr(self, obj_instance, attr_bit):

		matched_exprs = 0
		# logicaly AND-ed expressions
		expr_list = self.__classify_map[attr_bit]
		
		for expr in expr_list:
			field_info = expr[0]
			expected_values = expr[1]
			expected_res = expr[2]
			found = False

			field_info.set_value_from(obj_instance)

			for value in expected_values:

				found |= field_info.contains_value(value)

			if found == expected_res:
				matched_exprs += 1

		return matched_exprs == len(expr_list) if len(expr_list) > 0 else False

	def classify_object(self, obj_instance):
		attr_bits = 0

		for attr_bit in self.__classify_map.keys():
			res = self.__clarify_attr(obj_instance, attr_bit)
			if res:
				attr_bits |= attr_bit
		
		return attr_bits

	def get_values(self, field_name):
		values = []
		for attr_bit in self.__classify_map.keys():
			expr_list = self.__classify_map[attr_bit]
			for expr in expr_list:
				if expr[0].get_name() == field_name:
					expected_values = expr[1]
					for value in expected_values:
						if value not in values:
							values.append(value)

		return values