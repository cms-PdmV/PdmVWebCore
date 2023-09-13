"""
Logging configuration for middleware module

Attributes:
    logger (logging.Logger): Authentication middleware logger
    logger_handler (logging.StreamHandler): Shows log messages into the console
    logger_format (str): Log format
    logger_formatter (logging.Formatter): Applies the desired log format into the logger
"""
import logging

# Create a new logger
logger: logging.Logger = logging.getLogger("oauth2_proxy")
logger.setLevel(logging.INFO)

# Log into the console
logger_handler: logging.StreamHandler = logging.StreamHandler()
logger_handler.setLevel(logging.INFO)

# Logger format
logger_format: str = (
    "[AuthenticationMiddleware][%(levelname)s]"
    "[%(filename)s:%(funcName)s:%(lineno)s][%(asctime)s]: %(message)s"
)
logger_formatter: logging.Formatter = logging.Formatter(fmt=logger_format)
logger_handler.setFormatter(logger_formatter)
logger.addHandler(logger_handler)
