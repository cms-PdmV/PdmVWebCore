"""
This module contans UsernameFilter class
"""
import logging
from flask import has_request_context, session


class UsernameFilter(logging.Filter):
    """
    This is a filter that adds Adfs-Login value to the log
    """

    def filter(self, record):
        if has_request_context():
            user_data = session.get("user")
            if user_data:
                record.user = user_data.get("username")
            else:
                record.user = "<anonymous>"
        else:
            record.user = "main_thread"

        return True
