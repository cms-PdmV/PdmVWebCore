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
import time
import subprocess
from http.cookiejar import MozillaCookieJar
from dataclasses import asdict
from multiprocessing import Process
from flask import Flask, Blueprint, session, request, has_request_context
from middlewares.auth import AuthenticationMiddleware, UserInfo


class BaseTestCase(unittest.TestCase):
    """
    This class implements a base test case for implementing tests related to verify
    JWT validation features and OIDC flow implementation for authentication middleware.
    To achieve this, this class handles the life cycle for a simple Flask server that
    expose some protected resources required to test the authentication middleware.

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
    __USER_ENDPOINT__: str = "/test/user"
    __WEB_SERVER_HEARTBEAT_ENDPONT__: str = "/"
    __WEB_SERVER_HEARTBEAT_RESPONSE__: dict[str, str] = {
        "msg": "Web server deployed sucessfully"
    }
    __CERN_OAUTH_TOKEN_ENDPOINT: str = (
        "https://auth.cern.ch/auth/realms/cern/api-access/token"
    )
    __ANOTHER_OAUTH_ENDPOINT__: str = "https://cms-pdmv.cern.ch/valdb"

    def prepare_test(
        self,
        port: int = int(os.getenv("PORT", "-1")),
        client_id: str = os.getenv("CLIENT_ID", ""),
        client_secret: str = os.getenv("CLIENT_SECRET", ""),
        enable_oidc_flow: bool = False,
    ):
        self.host: str = "localhost"
        self.port: int = port
        self.client_id: str = client_id
        self.client_secret: str = client_secret
        self.secret_key: str = secrets.token_hex()
        self.__validate_environment()
        self.server: Process | None = None
        self.app, self.auth = self._create_test_flask_application(
            enable_oidc_flow=enable_oidc_flow
        )
        self.base_path: str = os.getcwd()
        self.static_folder: str = f"{self.base_path}/tests/middlewares/static"
        self.invalid_token: str = self.__retrieve_invalid_token(
            path=f"{self.static_folder}/invalid.json"
        )
        # Endpoints
        self.test_endpoint: str = (
            f"http://{self.host}:{self.port}"
            f"{BaseTestCase.__WEB_SERVER_HEARTBEAT_ENDPONT__}"
        )
        self.protected_endpoint: str = (
            f"http://{self.host}:{self.port}{BaseTestCase.__TEST_ENDPOINT__}"
        )
        self.user_endpoint: str = (
            f"http://{self.host}:{self.port}{BaseTestCase.__USER_ENDPOINT__}"
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

    def _create_test_flask_application(
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

        def __user_endpoint__() -> dict[str, str]:
            """
            Returns the user information available into the provided
            JWT for a valid authenticated HTTP request

            Returns:
                dict[str, str]: User information available inside a token
            """
            if has_request_context():
                user_info: UserInfo | None = session.get("user")
                if user_info:
                    return asdict(user_info)
            return {}

        # Create test app and install the middleware
        app: Flask = Flask(__name__)
        app.config["SECRET_KEY"] = self.secret_key
        auth: AuthenticationMiddleware = AuthenticationMiddleware(
            app=app,
            enable_oidc_flow=enable_oidc_flow,
            client_id=self.client_id,
            client_secret=self.client_secret,
            disable_secure_policy=True,
        )

        # Create a submodule for the protected resource
        protected: Blueprint = Blueprint("protected", __name__)
        protected.add_url_rule(rule="/", endpoint="test", view_func=__test_endpoint__)
        protected.add_url_rule(
            rule=f"/{BaseTestCase.__USER_ENDPOINT__.split('/')[-1]}",
            endpoint="user",
            view_func=__user_endpoint__,
        )
        # Configure the middleware before any HTTP request
        protected.before_request(
            lambda: auth.authenticate(request=request, flask_session=session)
        )
        app.register_blueprint(
            blueprint=protected,
            url_prefix=BaseTestCase.__TEST_ENDPOINT__,
        )

        # Install the heartbeat endpoint
        app.add_url_rule(
            rule="/",
            endpoint="heartbeat",
            view_func=__heartbeat_endpoint__,
        )

        return app, auth

    def __retrieve_invalid_token(self, path: str) -> str:
        """
        Retrieve an invalid JSON Web Token
        It will be useful to verify the functionality related to token validation

        Returns:
            str: An invalid JWT

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

    def _start_test_server(self) -> None:
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

    def _stop_test_server(self) -> None:
        """
        Stops the test web application that is currently running
        """
        if hasattr(self, "server") and isinstance(self.server, Process):
            if self.server.is_alive():
                self.server.kill()
            self.server = None

    def _request_application_token(self) -> tuple[int, str]:
        """
        Request an application JWT to CERN Authorization Server

        Returns:
            int: HTTP Response status code
            str: JWT retrieved from CERN Authorization Server
        """
        url_encoded_data: dict = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "audience": self.client_id,
        }
        response: requests.Response = requests.post(
            url=BaseTestCase.__CERN_OAUTH_TOKEN_ENDPOINT,
            data=url_encoded_data,
        )
        access_token: str = response.json().get("access_token", "")
        status_code: int = response.status_code
        return status_code, access_token

    def setUp(self) -> None:
        """
        Prepares all the test preconditions. For our context,
        it will start the test web application
        """
        super(BaseTestCase, self).setUp()
        self.prepare_test()
        self._start_test_server()
        time.sleep(0.125)

    def tearDown(self) -> None:
        """
        Destroys all the created resources for running this test,
        For our context, it shutdowns the test web application
        """
        super(BaseTestCase, self).tearDown()
        self._stop_test_server()
        time.sleep(0.125)

    def test_web_application(self) -> None:
        """
        Test that the test web application is available for performing requests.
        Send a HTTP request to the test web application and verify that the sample
        response is the same
        """
        response: requests.Response = requests.get(url=self.test_endpoint)
        body: dict = response.json()
        status_code: int = response.status_code

        self.assertEqual(
            200, status_code, msg="The HTTP response has an invalid status code"
        )
        self.assertEqual(
            body,
            BaseTestCase.__WEB_SERVER_HEARTBEAT_RESPONSE__,
            msg="The dummy response is different than expected",
        )


class JWTValidationTest(BaseTestCase):
    """
    This class check all the features related to validate an external
    JWT received via Authorization middleware
    """

    def setUp(self) -> None:
        """
        Prepares all the test preconditions. For our context,
        it will start the test web application
        """
        super(JWTValidationTest, self).setUp()

    def tearDown(self) -> None:
        """
        Destroys all the created resources for running this test,
        For our context, it shutdowns the test web application
        """
        super(JWTValidationTest, self).tearDown()

    def test_empty_jwt(self) -> None:
        """
        In case no JWT is provided into the Authorization header. The
        middleware must return a HTTP 401 response
        """
        response: requests.Response = requests.get(url=self.protected_endpoint)
        body: dict = response.json()
        expected_exception_msg: str = "Please provide a JWT"
        exception_msg: str = body.get("msg", "")

        self.assertEqual(
            401,
            response.status_code,
            msg="The middleware should have return a HTTP 401 Response: Unauthorized",
        )
        self.assertIn(
            expected_exception_msg,
            exception_msg,
            msg="The exception message is not the expected",
        )

    def test_request_token(self) -> None:
        """
        Check that we are able to properly request JWT
        to the authorization server
        """
        status_code, access_token = self._request_application_token()

        self.assertEqual(
            200, status_code, msg="The HTTP response has an invalid status code"
        )
        self.assertIsNotNone(
            self.auth.jwt_regex.search(access_token),
            msg="The HTTP does not have a valid formatted JWT",
        )

    def test_authenticated_resource(self) -> None:
        """
        Check access to a protected resource providing
        an Authorization JWT
        """
        _, access_token = self._request_application_token()
        headers: dict = {"Authorization": access_token}
        response: requests.Response = requests.get(
            url=self.protected_endpoint, headers=headers
        )
        body: dict = response.json()
        status_code: int = response.status_code

        self.assertEqual(
            200, status_code, msg="The HTTP response has an invalid status code"
        )
        self.assertEqual(
            body,
            BaseTestCase.__REQUEST_SUCCESS__,
            msg="The dummy response is different than expected",
        )

    def test_invalid_token(self) -> None:
        """
        Verify that we receive a HTTP 401 response if we provide an invalid JWT
        for authenticating to the application
        """
        access_token: str = self.invalid_token
        headers: dict = {"Authorization": access_token}
        response: requests.Response = requests.get(
            url=self.protected_endpoint, headers=headers
        )
        body: dict = response.json()
        status_code: int = response.status_code

        self.assertEqual(
            401, status_code, msg="The HTTP response has an invalid status code"
        )
        self.assertNotEqual(
            body,
            BaseTestCase.__REQUEST_SUCCESS__,
            msg="The dummy response is different than expected",
        )

    def test_user_info(self) -> None:
        """
        Verifies the user information stored into the Flask session cookie
        """
        _, access_token = self._request_application_token()
        headers: dict = {"Authorization": access_token}
        response: requests.Response = requests.get(
            url=self.user_endpoint, headers=headers
        )
        body: dict = response.json()
        status_code: int = response.status_code
        user_info: UserInfo = UserInfo(**body)
        dummy_application_name: str = f"service-account-{self.client_id}"

        self.assertEqual(
            200, status_code, msg="The HTTP response has an invalid status code"
        )
        self.assertEqual(
            user_info.username,
            dummy_application_name,
            msg="The application name into the token is not the expected",
        )
        self.assertEqual(
            user_info.email,
            user_info.username,
            msg="The email included into application JWT must be the same as the username",
        )
        self.assertEqual(
            "",
            user_info.fullname,
            msg="User fullname must be empty for application JWT",
        )


class SessionCookieTest(BaseTestCase):
    """
    This class implements some validation to check features related to
    OIDC flow handling directly by the application
    """

    def prepare_test(self):
        """
        Prepares the test case and enables OIDC flow for the middleware
        """
        super(SessionCookieTest, self).prepare_test(enable_oidc_flow=True)

    def __package_available(self, package: str) -> bool:
        """
        Check, via shell execution, if a desired package is available into the runtime
        environment.

        Args:
            package (str): Package to verify if exists

        Returns:
            bool: True if the package exists, False otherwise
        """
        result: subprocess.CompletedProcess = subprocess.run(
            f"which {package}", shell=True
        )
        return result.returncode == 0

    def __skip_cookie_tests(self) -> None:
        """
        Check if the runtime environment has the packages required to request
        session cookies via Kerberos authentication. If the are not available,
        this will skip all the test related with cookies and browser emulation
        (by convention, this tests will include the string: sso_cookie into its name)
        """
        self.skip_sso_cookie_test: bool = False

        # Is auth-get-sso-cookie package available?
        cookie_package: str = "auth-get-sso-cookie"
        cookie_package_available: bool = self.__package_available(
            package=cookie_package
        )
        kerberos_available: bool = self.__package_available(
            package="kinit"
        ) and self.__package_available(package="klist")
        if not cookie_package_available:
            logging.warn(
                "auth-get-sso-cookie package is not available, cookie test will be skipped"
            )
            self.skip_sso_cookie_test = True
        if not kerberos_available:
            logging.warn("Kerberos is not available, cookie test will be skipped")
            self.skip_sso_cookie_test = True

    def __request_sso_cookie(self, url: str | None = None) -> MozillaCookieJar:
        """
        Request a SSO cookie using auth-get-sso-cookie
        package for the test nginx middleware server.
        Please be sure to use the kerberos credentials for an account
        allowed by the application and for an account that does not
        have multifactor authentication enabled.

        Args:
            url: URL to request a session cookie. If this value is not provided
                the default `self.start_endpoint` will be used

        Returns:
            MozillaCookieJar: Cookies to authenticate to the
                middleware

        Raises:
            CalledProcessError: If there is an issue requesting the cookie
                to the SSO server
        """
        url = self.protected_endpoint if not url else url
        cookie_path: str = f"{self.static_folder}/cookie.txt"
        command: str = f"auth-get-sso-cookie -u {url} -o {cookie_path}"
        _: subprocess.CompletedProcess = subprocess.run(command, shell=True, check=True)
        cookie: MozillaCookieJar = MozillaCookieJar(filename=cookie_path)
        cookie.load()
        delete_cookie: str = f"rm -f {cookie_path}"
        _ = subprocess.run(delete_cookie, shell=True, check=True)
        return cookie

    def setUp(self) -> None:
        """
        Prepares all the test preconditions. For our context,
        it will start the test web application
        """
        super(BaseTestCase, self).setUp()
        self.prepare_test()
        self.__skip_cookie_tests()
        self._start_test_server()
        time.sleep(0.125)

    def tearDown(self) -> None:
        """
        Destroys all the created resources for running this test,
        For our context, it shutdowns the test web application
        """
        super(SessionCookieTest, self).tearDown()

    def test_request_sso_cookie(self) -> None:
        """
        Check that we are able to request sso cookies for
        the desired application
        """
        if self.skip_sso_cookie_test:
            raise unittest.SkipTest("CERN Auth CLI packages are not available")
        try:
            cookie: MozillaCookieJar = self.__request_sso_cookie()
            self.assertIsNotNone(cookie, msg="Cookie object is None")
        except subprocess.CalledProcessError as shell_error:
            logging.error("Error generating cookie: ", shell_error)
            self.assertTrue(False, msg="There was an error generating the SSO cookie")

    def test_valid_request_sso_cookie(self) -> None:
        """
        Check that a request providing a valid SSO cookie is accepted
        """
        if self.skip_sso_cookie_test:
            raise unittest.SkipTest("CERN Auth CLI packages are not available")

        access_cookie: MozillaCookieJar = self.__request_sso_cookie()
        response: requests.Response = requests.get(
            url=self.protected_endpoint, cookies=access_cookie
        )
        status_code: int = response.status_code
        body: dict = response.json()
        self.assertEqual(
            200,
            status_code,
            msg="Request should have been accepted but it was denied",
        )
        self.assertEqual(
            body,
            BaseTestCase.__REQUEST_SUCCESS__,
            msg="The dummy response is different than expected",
        )

    def test_invalid_request_sso_cookie(self) -> None:
        """
        Check that if a session cookie that belongs to another service is sent,
        the middleware starts automatically the process to retrieve a valid session cookie
        for the user and the desired page
        """
        if self.skip_sso_cookie_test:
            raise unittest.SkipTest("CERN Auth CLI packages are not available")

        access_cookie: MozillaCookieJar = self.__request_sso_cookie(
            url=BaseTestCase.__ANOTHER_OAUTH_ENDPOINT__
        )
        response: requests.Response = requests.get(
            url=self.protected_endpoint, cookies=access_cookie
        )
        status_code: int = response.status_code
        body: dict[str, str] = response.json()
        self.assertEqual(
            200,
            status_code,
            msg=(
                "Request should have finish successfully. "
                "A new session cookie should have been requested for the user"
            ),
        )
        self.assertEqual(
            body,
            BaseTestCase.__REQUEST_SUCCESS__,
            msg="The dummy response is different than expected",
        )
