"""
This module contans UsernameFilter class
"""
import logging
from flask import has_request_context, session
from ..middlewares.auth import UserInfo


class UsernameFilter(logging.Filter):
    """
    This is a filter that adds username value to the log
    """

    def filter(self, record):
        if has_request_context():
            user_data: UserInfo | None = session.get("user")
            if user_data and isinstance(user_data, UserInfo):
                record.user = user_data.username
            else:
                record.user = "<anonymous>"
        else:
            record.user = "main_thread"

        return True
