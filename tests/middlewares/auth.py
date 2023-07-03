"""
This module implements several tests to check the functionality
related to the Authentication Middleware. These test require
as prerrequisite to register a test application into CERN Application Portal
as public, to be able to request tokens on behalf of a application
"""

import unittest
import os
import logging
import json
import requests
import secrets
from multiprocessing import Process
from flask import Flask, Blueprint, session, request
from middlewares.auth import AuthenticationMiddleware


class BaseTestCase(unittest.TestCase):
    """
    This class implements the basic mechanisms for retriving the CLIENT_ID and CLIENT_SECRET
    required for requesting tokens to the authorization server. Likewise, this class
    handles the life cycle for a simple Flask server required to test the authentication
    middleware

    Attributes:
        port (int): Application port for deploying the test application
        client_id (str): Client ID required for requesting tokens from the authorization server
        client_secret (str): Client secret required to authenticate this test against the
            authorization server to request tokens
        app (Flask): A simple Flask application to install the Authentication Middleware and send
            some sample requests
        auth (AuthenticationMiddleware): OIDC authentication middleware
        secret_key (str): Flask secret key to sign the session cookie
        process_pool (ProcessPoolExecutor): A process pool executor to deploy the test
            Flask web server into another process
    """

    __REQUEST_SUCCESS__: dict[str, str] = {"msg": "Request successfully handled"}
    __TEST_ENDPOINT__: str = "/test"
    __WEB_SERVER_HEARTBEAT_ENDPONT__: str = "/"
    __WEB_SERVER_HEARTBEAT_RESPONSE__: dict[str, str] = {
        "msg": "Web server deployed sucessfully"
    }

    def prepare_test(
        self,
        port: int = int(os.getenv("PORT", "-1")),
        client_id: str = os.getenv("CLIENT_ID", ""),
        client_secret: str = os.getenv("CLIENT_SECRET", ""),
        enable_oidc_flow: bool = False,
    ):
        self.host: str = "127.0.0.1"
        self.port: int = port
        self.client_id: str = client_id
        self.client_secret: str = client_secret
        self.secret_key: str = secrets.token_hex()
        self.__validate_environment()
        self.server: Process | None = None
        self.app, self.auth = self.__create_test_flask_application(
            enable_oidc_flow=enable_oidc_flow
        )
        self.expired_token: str = self.__retrieve_expired_token(
            path="./tests/middlewares/static/expired.json"
        )
        # Supress Werkzeug log messages
        server_log: logging.Logger = logging.getLogger("werkzeug")
        server_log.disabled = True
        self.app.logger.disabled = True

    def __validate_environment(self) -> None:
        """
        Verifies that all required attributes are set with valid values

        Raises:
            ValueError: If one of the values to be validated has an incorrect value
        """
        msg: str = ""
        if not self.client_id:
            msg = (
                "Client ID is not set. "
                "Please set its value via the environment variable "
                "CLIENT_ID or via class constructor. "
                f"Current value: {self.client_id} - Type: {type(self.client_id)}"
            )
            raise ValueError(msg)
        if not self.client_secret:
            msg = (
                "Client secret is not set. "
                "Please set its value via the environment variable "
                "CLIENT_SECRET or via class constructor. "
                f"Current value: {self.client_secret} - Type: {type(self.client_secret)}"
            )
            raise ValueError(msg)
        if self.port == -1:
            msg = "Please set a free port for deploying the web server"
            raise ValueError(msg)

    def __create_test_flask_application(
        self, enable_oidc_flow: bool = False
    ) -> tuple[Flask, AuthenticationMiddleware]:
        """
        This functions configures a test Flask application and installs
        the AuthenticationMiddleware in order to have a test web application to
        execute requests

        Args:
            enable_oidc_flow (bool): Enable OIDC authentication flow for the middleware

        Returns:
            Flask: Flask application to perform the tests
            AuthenticationMiddleware: Middleware installed into the app
        """

        def __test_endpoint__() -> dict[str, str]:
            """
            Returns a sample response to simulate a resource consumed for a
            request successfully authenticated.

            Returns:
                dict[str, str]: A sample response
            """
            return BaseTestCase.__REQUEST_SUCCESS__

        def __heartbeat_endpoint__() -> dict[str, str]:
            """
            Returns a sample response to simulate an
            unprotected resource consumed for a request.

            Returns:
                dict[str, str]: A sample response
            """
            return BaseTestCase.__WEB_SERVER_HEARTBEAT_RESPONSE__

        # Create test app and install the middleware
        app: Flask = Flask(__name__)
        app.config["SECRET_KEY"] = self.secret_key
        auth: AuthenticationMiddleware = AuthenticationMiddleware(
            app=app,
            enable_oidc_flow=enable_oidc_flow,
            client_id=self.client_id,
            client_secret=self.client_secret,
        )

        # Create a submodule for the protected resource
        protected: Blueprint = Blueprint("protected", __name__)
        protected.add_url_rule(rule="/", endpoint="test", view_func=__test_endpoint__)
        # Configure the middleware before any HTTP request
        protected.before_request(
            lambda: auth.authenticate(request=request, flask_session=session)
        )
        app.register_blueprint(
            blueprint=protected, url_prefix=BaseTestCase.__TEST_ENDPOINT__
        )

        # Install the heartbeat endpoint
        app.add_url_rule(
            rule="/",
            endpoint="heartbeat",
            view_func=__heartbeat_endpoint__,
        )

        return app, auth

    def __retrieve_expired_token(self, path: str) -> str:
        """
        Retrieve an expired JSON Web Token requested to the CERN Authorization Server
        It will be useful to verify the functionality related to token validation

        Returns:
            str: A expired JWT provided by CERN Authorization Server

        Raises:
            ValueError: If the retrieved token is empty
        """
        with open(file=path, mode="r", encoding="utf-8") as f:
            token_file = json.load(fp=f)

        # Retrieve the token
        token: str = token_file.get("token", "")
        if not token:
            raise ValueError("The static JWT is empty: ", token)

        return token

    def __start_test_server(self) -> None:
        """
        Starts the test web application to handle some test request
        to test the functionality
        """

        def __start__(app: Flask, host: str, port: int):
            """
            Starts the web server using Werkzeug to run in localhost
            and into the desired port.

            Args:
                app (Flask): Flask application to run
                port (int): Port where the application is going to be executed
            """
            # Send test web server output to /dev/null
            app.run(host=host, port=port, debug=False, use_reloader=False)

        # Only start if there is not a running server already
        if not isinstance(self.server, Process):
            self.server = Process(
                target=__start__, args=(self.app, self.host, self.port)
            )
            self.server.start()

    def __stop_test_server(self) -> None:
        """
        Stops the test web application that is currently running
        """
        if hasattr(self, "server") and isinstance(self.server, Process):
            if self.server.is_alive():
                self.server.kill()
            self.server = None

    def setUp(self) -> None:
        """
        Prepares all the test preconditions. For our context,
        it will start the test web application
        """
        super(BaseTestCase, self).setUp()
        self.prepare_test()
        self.__start_test_server()

    def tearDown(self) -> None:
        """
        Destroys all the created resources for running this test,
        For our context, it shutdowns the test web application
        """
        super(BaseTestCase, self).tearDown()
        self.__stop_test_server()

    def test_web_application(self) -> None:
        """
        Test that the test web application is available for performing requests.
        Send a HTTP request to the test web application and verify that the sample
        response is the same
        """
        endpoint: str = f"http://{self.host}:{self.port}{BaseTestCase.__WEB_SERVER_HEARTBEAT_ENDPONT__}"
        dummy_response: dict = requests.get(url=endpoint).json()
        self.assertEqual(
            dummy_response,
            BaseTestCase.__WEB_SERVER_HEARTBEAT_RESPONSE__,
            msg="The dummy response is different than expected",
        )
