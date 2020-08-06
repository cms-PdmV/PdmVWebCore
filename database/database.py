"""
A module that handles all communication with MongoDB
"""
import logging
import time
import json
import os
from pymongo import MongoClient


class Database():
    """
    Database class represents a particular collection in MongoDB
    """

    __DATABASE_HOST = 'localhost'
    __DATABASE_PORT = 27017
    __DATABASE_NAME = None
    __SEARCH_RENAME = {}
    __USERNAME = None
    __PASSWORD = None

    def __init__(self, collection_name=None):
        """
        Constructor of database interface
        """
        self.collection_name = collection_name
        self.logger = logging.getLogger()
        db_host = os.environ.get('DB_HOST', Database.__DATABASE_HOST)
        db_port = os.environ.get('DB_PORT', Database.__DATABASE_PORT)
        if not Database.__DATABASE_NAME:
            raise Exception('Database name is not set')

        if Database.__USERNAME and Database.__PASSWORD:
            self.logger.debug('Using DB with username and password')
            self.client = MongoClient(db_host,
                                      db_port,
                                      username=Database.__USERNAME,
                                      password=Database.__PASSWORD,
                                      authSource='admin',
                                      authMechanism='SCRAM-SHA-256')[Database.__DATABASE_NAME]
        else:
            self.logger.debug('Using DB without username and password')
            self.client = MongoClient(db_host, db_port)[Database.__DATABASE_NAME]

        self.collection = self.client[collection_name]

    @classmethod
    def set_host_port(cls, host, port):
        """
        Set global database hostname and port
        """
        cls.__DATABASE_HOST = host
        cls.__DATABASE_PORT = port

    @classmethod
    def set_database_name(cls, database_name):
        """
        Set global database name
        """
        cls.__DATABASE_NAME = database_name

    @classmethod
    def add_search_rename(cls, collection, value, renamed_value):
        """
        Add a global rename rule to query method
        """
        if collection not in cls.__SEARCH_RENAME:
            cls.__SEARCH_RENAME[collection] = {}

        cls.__SEARCH_RENAME[collection][value] = renamed_value

    @classmethod
    def set_credentials(cls, username, password):
        """
        Set database username and password
        """
        cls.__USERNAME = username
        cls.__PASSWORD = password

    @classmethod
    def set_credentials_file(cls, filename):
        """
        Load credentials from a JSON file
        """
        with open(filename) as json_file:
            credentials = json.load(json_file)

        cls.set_credentials(credentials['username'], credentials['password'])

    def get_count(self):
        """
        Get number of documents in the database
        """
        return self.collection.count_documents({})

    def get(self, document_id):
        """
        Get a single document with given identifier
        """
        result = self.collection.find_one({'_id': document_id})
        if result and 'last_update' in result:
            del result['last_update']

        return result

    def document_exists(self, document_id):
        """
        Do a GET request to check whether document exists
        """
        response = self.get(document_id)
        return bool(response)

    def delete_document(self, document):
        """
        Delete a document
        """
        if not isinstance(document, dict):
            self.logger.error('%s is not a dictionary', document)
            return

        document_id = document.get('_id', '')
        document_id = document_id.strip()
        if not document_id:
            self.logger.error('%s does not have a _id', document)
            return

        self.collection.delete_one({'_id': document_id})

    def save(self, document):
        """
        Save a document
        """
        if not isinstance(document, dict):
            self.logger.error('%s is not a dictionary', document)
            return False

        document_id = document.get('_id', '')
        if not document_id:
            self.logger.error('%s does not have a _id', document)
            return False

        document['last_update'] = int(time.time())
        if self.document_exists(document_id):
            self.logger.debug('Updating %s', document_id)
            return self.collection.replace_one({'_id': document_id}, document)

        self.logger.debug('Creating %s', document_id)
        return self.collection.insert_one(document)

    def query(self,
              query_string=None,
              page=0, limit=20,
              sort_attr=None, sort_asc=True):
        """
        Same as query_with_total_rows, but return only list of objects
        """
        return self.query_with_total_rows(query_string, page, limit, sort_attr, sort_asc)[0]

    def query_with_total_rows(self,
                              query_string=None,
                              page=0, limit=20,
                              sort_attr=None, sort_asc=True):
        """
        Perform a query in a database
        And operator is &&
        Example prepid=*19*&&is_root=false
        This is horrible, please think of something better
        """
        query_dict = {}
        if query_string:
            query_dict = {'$and': []}
            query_string_parts = [x.strip() for x in query_string.split('&&') if x.strip()]
            self.logger.info('Query parts %s', query_string_parts)
            for part in query_string_parts:
                split_part = part.split('=')
                key = split_part[0]
                value = split_part[1].replace('*', '.*')
                value_condition = None
                if '<' in value[0]:
                    value_condition = '$lt'
                    value = value[1:]
                elif value[0] == '>':
                    value_condition = '$gt'
                    value = value[1:]
                elif value[0] == '!':
                    value_condition = '$ne'
                    value = value[1:]

                if '<int>' in key:
                    value = int(value)
                    if value_condition:
                        value = {value_condition: value}

                    query_dict['$and'].append({key.replace('<int>', ''): value})
                elif '<float>' in key:
                    value = float(value)
                    if value_condition:
                        value = {value_condition: value}

                    query_dict['$and'].append({key.replace('<float>', ''): value})
                else:
                    if value_condition:
                        value = {value_condition: value}
                        query_dict['$and'].append({key: value})
                    elif '*' in value:
                        query_dict['$and'].append({key: {'$regex': value}})
                    else:
                        query_dict['$and'].append({key: value})

        self.logger.debug('Database "%s" query dict %s', self.collection_name, query_dict)
        result = self.collection.find(query_dict)
        if not sort_attr:
            sort_attr = '_id'

        result = result.sort(sort_attr, 1 if sort_asc else -1)
        total_rows = result.count()
        result = result.skip(page * limit).limit(limit)
        return list(result), int(total_rows)

    def build_query_with_types(self, query_string, object_class):
        """
        This is horrible, please think of something better
        """
        schema = object_class.schema()
        query_string_parts = [x.strip() for x in query_string.split('&&') if x.strip()]
        typed_arguments = []
        for part in query_string_parts:
            split_part = part.split('=')
            key = split_part[0]
            value = split_part[1]
            if key in Database.__SEARCH_RENAME.get(self.collection_name, {}):
                key = Database.__SEARCH_RENAME[self.collection_name][key]
            elif isinstance(schema.get(key), (int, float)):
                key = f'{key}<{type(schema.get(key)).__name__}>'

            typed_arguments.append(f'{key}={value}')

        return '&&'.join(typed_arguments)
