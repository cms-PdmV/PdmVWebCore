"""
Module that contains ControllerBase class
"""
import logging
from core.database.database import Database
from core.model.model_base import ModelBase
from core.utils.locker import Locker


class ControllerBase():
    """
    Controller base class implements simple create, read, update, delete methods
    as well as some convenience methods such as get_changed_values for update
    It also has callback methods that are called before create, update or delete actions
    This is a base class for all controllers
    It requires database name and class object of model
    """

    def __init__(self):
        self.logger = logging.getLogger()
        self.locker = Locker()
        self.database_name = None
        self.model_class = ModelBase

    def create(self, json_data):
        """
        Create a new object from given json_data
        """
        json_data['history'] = []
        if '_id' in json_data:
            del json_data['_id']

        new_object = self.model_class(json_input=json_data)
        prepid = new_object.get_prepid()

        database = Database(self.database_name)
        if database.get(prepid):
            raise Exception(f'Object with prepid "{prepid}" already '
                            f'exists in {self.database_name} database')

        with self.locker.get_lock(prepid):
            self.logger.info('Will create %s', (prepid))
            new_object.add_history('create', prepid, None)
            if not self.check_for_create(new_object):
                self.logger.error('Error while checking new item %s', prepid)
                return None

            self.before_create(new_object)
            if not database.save(new_object.get_json()):
                raise Exception(f'Error saving {prepid} to database')

        return new_object

    def get(self, prepid):
        """
        Return a single object if it exists in database
        """
        database = Database(self.database_name)
        object_json = database.get(prepid)
        if object_json:
            return self.model_class(json_input=object_json)

        return None

    def update(self, json_data, force_update=False):
        """
        Update a single object with given json
        """
        new_object = self.model_class(json_input=json_data)
        prepid = new_object.get_prepid()
        with self.locker.get_nonblocking_lock(prepid):
            self.logger.info('Will edit %s', prepid)
            database = Database(self.database_name)
            old_object_json = database.get(prepid)
            if not old_object_json:
                raise Exception(f'Object with prepid "{prepid}" does not '
                                f'exist in {self.database_name} database')

            old_object = self.model_class(json_input=old_object_json)
            # Move over history, so it could not be overwritten
            new_object.set('history', old_object.get('history'))
            changed_values = self.get_changes(old_object_json, new_object.get_json())
            if not changed_values:
                # Nothing was updated
                self.logger.info('Nothing was updated for %s', prepid)
                return old_object.get_json()

            if not force_update:
                self.edit_allowed(old_object, changed_values)
                new_object.add_history('update', changed_values, None)
                if not self.check_for_update(old_object, new_object, changed_values):
                    self.logger.error('Error while updating %s', prepid)
                    return None

            self.before_update(new_object)
            database.save(new_object.get_json())
            return new_object.get_json()

    def delete(self, json_data):
        """
        Delete a single object
        """
        prepid = json_data.get('prepid', None)
        database = Database(self.database_name)
        json_data = database.get(prepid)
        if not json_data:
            raise Exception(f'Object with prepid "{prepid}" does not '
                            f'exist in {self.database_name} database')

        obj = self.model_class(json_input=json_data)
        with self.locker.get_nonblocking_lock(prepid, f'Deleting {prepid}'):
            self.logger.info('Will delete %s', (prepid))
            if not self.check_for_delete(obj):
                self.logger.error('Error while deleting %s', prepid)
                return None

            self.before_delete(obj)
            database.delete_document(obj.get_json())

        return {'prepid': prepid}

    def check_for_create(self, obj):
        """
        Perform checks on object before adding it to database
        """
        return True

    def check_for_update(self, old_obj, new_obj, changed_values):
        """
        Compare existing and updated objects to see if update is valid
        """
        return True

    def check_for_delete(self, obj):
        """
        Perform checks on object before deleting it from database
        """
        return True

    def before_create(self, obj):
        """
        Actions to be performed on object before object is updated
        """
        return

    def before_update(self, obj):
        """
        Actions to be performed on object before object is updated
        """
        return

    def before_delete(self, obj):
        """
        Actions to be performed on object before object is deleted
        """
        return

    def get_editing_info(self, obj):
        """
        Return a dictionary of pairs where key is attribute name and value is
        a boolean whether that attribute can be edited, for example
        {
          "prepid": False,
          "notes": True
        }
        """
        return {k: False for k in obj.get_json().keys()}

    def edit_allowed(self, obj, changed_values):
        """
        Check whether done edit is allowed based on editing info
        and changed values
        """
        editing_info = self.get_editing_info(obj)
        if not editing_info:
            return True

        for changed_value in changed_values:
            changed_value_trimmed = changed_value.split('.')[0].split('[')[0]
            allowed = editing_info.get(changed_value_trimmed, False)
            if not allowed:
                raise Exception(f'It is not allowed to change value of "{changed_value_trimmed}"')

        return True

    def get_changes(self, reference, target, prefix=None, changed_values=None):
        """
        Get dictionary of different values across two objects
        """
        if changed_values is None:
            changed_values = []

        if prefix is None:
            prefix = ''

        if isinstance(reference, ModelBase):
            reference = reference.get_json()

        if isinstance(target, ModelBase):
            target = target.get_json()

        if isinstance(reference, dict) and isinstance(target, dict):
            # Comparing two dictionaries
            keys = set(reference.keys()).union(set(target.keys()))
            for key in keys:
                self.get_changes(reference.get(key),
                                 target.get(key),
                                 '%s.%s' % (prefix, key),
                                 changed_values)
        elif isinstance(reference, list) and isinstance(target, list):
            # Comparing two lists
            if len(reference) != len(target):
                changed_values.append(prefix.lstrip('.').lstrip('_'))
            else:
                for i in range(min(len(reference), len(target))):
                    self.get_changes(reference[i],
                                     target[i],
                                     '%s[%s]' % (prefix, i),
                                     changed_values)
        else:
            # Comparing two values
            if reference != target:
                changed_values.append(prefix.lstrip('.').lstrip('_'))

        return changed_values

    def get_highest_serial_number(self, database, query):
        """
        Return highest sequence number of existing object
        If object does not exist return 0
        """
        serial_numbers = database.query(f'prepid={query}',
                                        limit=1,
                                        sort_asc=False)
        if not serial_numbers:
            serial_number = 0
        else:
            serial_number = serial_numbers[0]['prepid']
            serial_number = int(serial_number.split('-')[-1])

        self.logger.debug('Highest serial number for %s is %s', query, serial_number)
        return serial_number
