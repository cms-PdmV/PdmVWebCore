"""
Module that contains UserInfo class
"""
from flask import session
from ..utils.settings import Settings
from ..utils.cache import TimeoutCache


class UserInfo:
    """
    Class that holds information about user
    Information is obtained from headers supplied by SSO proxy
    """

    __cache = TimeoutCache()

    def __init__(self):
        self.__user = None
        self.__role_groups = self.__get_role_groups()
        self.__roles = self.__get_roles(self.__role_groups)

    @classmethod
    def __get_roles(cls, role_groups):
        """
        Return list of role names
        """
        cached_value = UserInfo.__cache.get("roles")
        if cached_value:
            return cached_value

        roles = [x["role"] for x in role_groups]
        UserInfo.__cache.set("roles", roles)
        return roles

    @classmethod
    def __get_role_groups(cls):
        """
        Return list of dictionaries where each dict has a "groups" list of e-groups
        and a "role" which is the role name
        """
        cached_value = UserInfo.__cache.get("role_groups")
        if cached_value:
            return cached_value

        role_groups = Settings().get("roles")
        for group in role_groups:
            group["groups"] = set(group.get("groups", []))
            group["users"] = set(group.get("users", []))

        UserInfo.__cache.set("role_groups", role_groups)
        return role_groups

    def __get_user_info_keycloak_sso(self):
        """
        Check session cookie and parse user information using
        authentication information from CERN Single Sign On: Keycloak
        """
        # Assume the user is already authenticated
        # This reponsibility relies on the Authentication middleware
        # If you require more details, please see: middlewares/auth.py
        user_data: dict = session.get("user", {})

        # TODO: In the near future, migrate all applications to use roles instead of e-group names.
        # Delegate this responsibility only to CERN Application Portal.
        # Keep inside all user databases only a history of permissions changes.
        # For this moment, the role will have the same name the required e-group has
        groups = user_data.get("roles", [])
        username = user_data.get("username", "")
        fullname = user_data.get("fullname", "")
        name = user_data.get("given_name", "")
        lastname = user_data.get("family_name")

        user_role = "user"
        groups_set = set(groups)
        for role_group in reversed(self.__role_groups):
            if (role_group["groups"] & groups_set) or (username in role_group["users"]):
                user_role = role_group["role"]
                break

        role_index = self.__roles.index(user_role)
        return {
            "name": name,
            "lastname": lastname,
            "fullname": fullname,
            "username": username,
            # 'groups': groups,
            "role": user_role,
            "role_index": role_index,
        }

    def get_user_info(self):
        """
        Check session cookie and parse user information
        """
        if not self.__user:
            self.__user = self.__get_user_info_keycloak_sso()

        return self.__user

    def get_username(self):
        """
        Get username, i.e. login name
        """
        return self.get_user_info()["username"]

    def get_user_name(self):
        """
        Get user name and last name
        """
        return self.get_user_info()["name"]

    def get_groups(self):
        """
        Get list of groups that user is member of
        """
        return self.get_user_info()["groups"]

    def get_role(self):
        """
        Get list of groups that user is member of
        """
        return self.get_user_info()["role"]

    def role_index_is_more_or_equal(self, role_name):
        """
        Return whether this user has equal or higher role
        """
        return self.__roles.index(role_name) <= self.__roles.index(self.get_role())
