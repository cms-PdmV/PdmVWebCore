"""
Module that contains global config singleton
"""
import configparser

class Config():
    """
    Global config holder
    """

    __CONFIG_VALUES = {}

    def __init__(self):
        pass

    @classmethod
    def load(cls, filename, section):
        """
        Get config as a dictionary
        Load only one section
        """
        config = configparser.ConfigParser()
        config.read(filename)
        config = dict(config.items(section))
        cls.__CONFIG_VALUES = config

        return config

    @classmethod
    def get(cls, key, default=None):
        """
        Get a single value from loaded config
        """
        value = cls.__CONFIG_VALUES.get(key, default)
        return value
