"""
Module that contains ModelBase class
"""
import json
import logging
import re
import time
from copy import deepcopy
from ..utils.user_info import UserInfo
from ..utils.common_utils import clean_split


class ModelBase():
    """
    Base class for all model objects
    Has some convenience methods as well as somewhat smart setter
    Contains a bunch of sanity checks
    """
    __json = {}
    __schema = {}
    __model_name = None
    __logger = logging.getLogger()
    __class_name = None
    default_lambda_checks = {}
    lambda_checks = {}

    def __init__(self, json_input=None, check_attributes=True):
        self.__json = {}
        self.logger = ModelBase.__logger
        self.__class_name = self.__class__.__name__
        self.initialized = False

        if json_input is None:
            json_input = self.schema()
            check_attributes = False

        if not check_attributes:
            self.logger.debug('Creating %s object, using given JSON',
                              self.__class_name)
            self.__json = json_input
        else:
            self.logger.debug('Creating %s object. JSON input present: %s',
                              self.__class_name,
                              'YES' if json_input else 'NO')
            self.__fill_values(json_input)

        self.initialized = True

    def __fill_values(self, json_input):
        """
        Copy values from given dictionary to object's json
        Initialize default values from schema if any are missing
        """
        if json_input and ('prepid' in self.__schema or '_id' in self.__schema):
            prepid = json_input.get('prepid')
            if not prepid:
                raise Exception('PrepID cannot be empty')

            # Remove prepid and _id from provided dict
            json_input.pop('prepid', None)
            json_input.pop('_id', None)
            self.set('prepid', prepid)
            self.set('_id', prepid)

        self.__fill_values_dict(json_input, self.__json, self.__schema)

    def __fill_values_dict(self, source_dict, target_dict, schema_dict):
        for key, default_value in schema_dict.items():
            if key in ('prepid', '_id'):
                # prepid and _id should not be set here
                continue

            if isinstance(default_value, dict) and default_value:
                # Default value here is another dict from schema
                # It will be used not as value, but as new schema
                target_dict[key] = {}
                self.__fill_values_dict(source_dict.get(key, {}),
                                        target_dict[key],
                                        default_value)
            elif key not in source_dict:
                # Copy default value from schema
                target_dict[key] = deepcopy(default_value)
            else:
                # Set value from source dict
                self.__set(target_dict,
                           key,
                           source_dict[key],
                           default_value)

    def __set(self, target_dict, attribute, value, value_in_schema):
        if not isinstance(value, type(value_in_schema)):
            prepid = self.get_prepid()
            self.logger.debug('%s of %s is not expected (%s) type (got %s). Will try to cast',
                              attribute,
                              prepid,
                              type(value_in_schema),
                              type(value))
            value = self.cast_value_to_correct_type(attribute, value, value_in_schema)

        if isinstance(value, str):
            value = value.strip()

        if not self.check_attribute(attribute, value):
            prepid = self.get_prepid()
            self.logger.error('Invalid value "%s" for key "%s" for object %s of type %s',
                              value,
                              attribute,
                              prepid,
                              self.__class_name)
            raise Exception(f'Invalid {attribute} value {value} for {prepid}')

        target_dict[attribute] = value

    def set(self, attribute, value=None):
        """
        Set attribute of the object
        """
        if not attribute:
            raise Exception('Attribute name not specified')

        if '.' in attribute:
            target_dict = self.__get_parent_dict(attribute)
            attribute = clean_split(attribute, '.')[-1]
            schema = self.__get_parent_dict(self.__schema)
        else:
            target_dict = self.__json
            schema = self.__schema

        self.__set(target_dict, attribute, value, schema[attribute])
        if attribute == 'prepid':
            self.__json['_id'] = value

        return self.__json

    def __get_parent_dict(self, attribute_path):
        parent_dict = self.__json
        path = clean_split(attribute_path, '.')[:-1]
        visited = []
        while path:
            step = path.pop(0)
            if step not in parent_dict:
                raise Exception(f'Could not find {step} in {".".join(visited)}')

            visited.append(step)
            parent_dict = parent_dict[step]

        return parent_dict

    def get(self, attribute):
        """
        Get attribute of the object
        """
        if not attribute:
            raise Exception('Attribute name not specified')

        if '.' in attribute:
            target_dict = self.__get_parent_dict(attribute)
            attribute = clean_split(attribute, '.')[-1]
        else:
            target_dict = self.__json

        return target_dict[attribute]

    def get_prepid(self):
        """
        Return prepid or _id if any of it exist
        Return none if it doesn't
        """
        if 'prepid' in self.__json:
            return self.__json['prepid']

        if '_id' in self.__json:
            return self.__json['_id']

        return None

    def check_attribute(self, attribute_name, attribute_value):
        """
        This method must return whether given value of attribute is valid
        or raise exception with error
        First it tries to find exact name match in lambda functions
        Then it checks for lambda function with double underscore prefix which
        indicates that this is a list of values
        """
        if attribute_name in self.lambda_checks:
            if not self.lambda_checks[attribute_name](attribute_value):
                return False

        # List
        if f'__{attribute_name}' in self.lambda_checks:
            if not isinstance(attribute_value, list):
                raise Exception(f'Expected {attribute_name} to be a list')

            lambda_check = self.lambda_checks[f'__{attribute_name}']
            for item in attribute_value:
                if not lambda_check(item):
                    raise Exception(f'Bad {attribute_name} value "{item}"')

        # Dict
        if f'_{attribute_name}' in self.lambda_checks:
            if not isinstance(attribute_value, dict):
                raise Exception(f'Expected {attribute_name} to be a dict')

            lambda_checks = self.lambda_checks[f'_{attribute_name}']
            invalid_keys = set(attribute_value.keys()) - set(lambda_checks.keys())
            if invalid_keys:
                raise Exception(f'Keys {",".join(invalid_keys)} are not '
                                f'allowed in {attribute_name}')

            for key, lambda_check in lambda_checks.items():
                value = attribute_value[key]
                if not lambda_check(value):
                    raise Exception(f'Bad {key} value "{value}" in {attribute_name} dictionary')

        return True

    def cast_value_to_correct_type(self, attribute, value, value_in_schema):
        """
        If value is not correct type, try to cast it to
        correct type according to schema
        """
        expected_type = type(value_in_schema)
        got_type = type(value)
        if expected_type == list and got_type == str:
            # If expected a list, but got a string, split by comma
            return clean_split(value, ',')

        try:
            return expected_type(value)
        except Exception as ex:
            expected_type_name = expected_type.__name__
            got_type_name = got_type.__name__
            prepid = self.get_prepid()
            self.logger.error(ex)
            raise Exception(f'Object {prepid} attribute {attribute} is wrong type. '
                            f'Expected {expected_type_name}, got {got_type_name}. '
                            f'It cannot be automatically casted to correct type')

    @classmethod
    def matches_regex(cls, value, regex):
        """
        Check if given string fully matches given regex
        """
        matcher = re.compile(regex)
        match = matcher.fullmatch(value)
        if match:
            return True

        return False

    def __get_json(self, item):
        """
        Internal method to recursively create dict representations of objects
        """
        if isinstance(item, ModelBase):
            return item.get_json()

        if isinstance(item, list):
            new_list = []
            for element in item:
                new_list.append(self.__get_json(element))

            return new_list

        return item

    def get_json(self):
        """
        Return JSON of the object
        """
        built_json = {}
        for attribute, value in self.__json.items():
            built_json[attribute] = self.__get_json(value)

        return deepcopy(built_json)

    @classmethod
    def schema(cls):
        """
        Return a copy of scema
        """
        return deepcopy(cls.__schema)

    def __str__(self):
        """
        String representation of the object
        """
        object_json = self.get_json()
        if 'history' in object_json:
            del object_json['history']

        return (f'Object ID: {self.get_prepid()}\n'
                f'Type: {self.__class_name}\n'
                f'Dict: {json.dumps(object_json, indent=2, sort_keys=True)}')

    def add_history(self, action, value, user, timestamp=None):
        """
        Add entry to object's history
        If no time is specified, use current time
        """
        if user is None:
            user = UserInfo().get_username()

        history = self.get('history')
        history.append({'action': action,
                        'time': int(timestamp if timestamp else time.time()),
                        'user': user,
                        'value': value})
        self.set('history', history)

    @classmethod
    def lambda_check(cls, name):
        """
        Return a lambda check from default lambda checks dictionary
        """
        return cls.default_lambda_checks.get(name)
