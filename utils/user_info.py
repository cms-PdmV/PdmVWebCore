"""
Module that contains UserInfo class
"""
from flask import request
from ..utils.settings import Settings
from ..utils.cache import TimeoutCache


class UserInfo():
    """
    Class that holds information about user
    Information is obtained from headers supplied by SSO proxy
    """
    __cache = TimeoutCache()

    def __init__(self):
        self.__user = None
        self.__role_groups = self.__get_role_groups()
        self.__roles = self.__get_roles()

    def __get_roles(self):
        """
        Return list of role names
        """
        cached_value = self.__cache.get('roles')
        if cached_value:
            return cached_value

        roles = [x['role'] for x in self.__role_groups]
        self.__cache.set('roles', roles)
        return roles

    def __get_role_groups(self):
        """
        Return list of dictionaries where each dict has a "groups" list of e-groups
        and a "role" which is the role name
        """
        cached_value = self.__cache.get('role_groups')
        if cached_value:
            return cached_value

        role_groups = Settings().get('roles')
        for group in role_groups:
            group['groups'] = set(group.get('groups', []))
            group['users'] = set(group.get('users', []))

        self.__cache.set('role_groups', role_groups)
        return role_groups

    def get_user_info(self):
        """
        Check request headers and parse user information
        """
        if not self.__user:
            groups = request.headers.get('Adfs-Group', '').split(';')
            groups = [x.strip().lower() for x in groups if x.strip()]
            username = request.headers.get('Adfs-Login')
            fullname = request.headers.get('Adfs-Fullname')
            name = request.headers.get('Adfs-Firstname')
            lastname = request.headers.get('Adfs-Lastname')
            user_role = 'user'
            groups_set = set(groups)
            for role_group in reversed(self.__role_groups):
                if (role_group['groups'] & groups_set) or (username in role_group['users']):
                    user_role = role_group['role']
                    break

            role_index = self.__roles.index(user_role)
            self.__user = {'name': name,
                           'lastname': lastname,
                           'fullname': fullname,
                           'username': username,
                           # 'groups': groups,
                           'role': user_role,
                           'role_index': role_index}

        return self.__user

    def get_username(self):
        """
        Get username, i.e. login name
        """
        return self.get_user_info()['username']

    def get_user_name(self):
        """
        Get user name and last name
        """
        return self.get_user_info()['name']

    def get_groups(self):
        """
        Get list of groups that user is member of
        """
        return self.get_user_info()['groups']

    def get_role(self):
        """
        Get list of groups that user is member of
        """
        return self.get_user_info()['role']

    def role_index_is_more_or_equal(self, role_name):
        """
        Return whether this user has equal or higher role
        """
        return self.__roles.index(role_name) <= self.__roles.index(self.get_role())
