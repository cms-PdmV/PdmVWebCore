"""
This module groups all the test cases and enables to execute
all of them. Just import the test into the namespace
"""
import unittest
from tests.middlewares.auth import JWTValidationTest, SessionCookieTest

if __name__ == "__main__":
    unittest.main(verbosity=2)
