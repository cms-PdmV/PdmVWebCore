"""
This module implements an authentication middleware to
enable OIDC authentication for Flask applications.
"""

from dataclasses import dataclass, field
import os
import re
import jwt
from jwt.exceptions import InvalidTokenError, ExpiredSignatureError
from authlib.integrations.flask_client import OAuth
from werkzeug.exceptions import HTTPException
from werkzeug.wrappers.response import Response
from flask.sessions import SessionMixin
from flask import (
    Flask,
    Blueprint,
    Request,
    session,
    redirect,
    url_for,
    jsonify,
)
from .logger import logger


@dataclass(frozen=True)
class UserInfo:
    """
    Store the user information available from a
    JWT retrieved via CERN SSO authentication server

    Attributes:
        username (str): CERN username. This field stores the data
            available under the "sub" claim into the JWT.
        roles (list[str]): List of roles a user has for
            an application. This field stores the data
            available under the "cern_roles" claim into the JWT.
        email (str): User's email. This field is going to be empty
            if the parsed token is related to an application.
            This field stores the data available
            under the "email" claim into the JWT.
        given_name (str): User's name.
            This field is going to be empty
            if the parsed token is related to an application.
            This field stores the data available
            under the "given_name" claim into the JWT.
        given_name (str): User's last name.
            This field is going to be empty
            if the parsed token is related to an application.
            This field stores the data available
            under the "family_name" claim into the JWT.
        fullname (str): User's fullname.
            This field is going to be empty
            if the parsed token is related to an application.
            This field stores the data available
            under the "fullname" claim into the JWT.
    """

    username: str = ""
    roles: list[str] = field(default_factory=list[str])
    email: str = ""
    given_name: str = ""
    family_name: str = ""
    fullname: str = ""


class AuthenticationMiddleware:
    """
    This class sets OIDC authentication for a Flask application
    By default, it will attempt to verify JWT provided by an OAuth2 proxy
    like the standard CERN Auth Proxy.
    Nevertheless, this component is also able to handle the OIDC flow itself
    to include this authentication mechanism directly into the application.

    Attributes:
        app (Flask): Flask application to set this middleware
        enable_oidc_flow (bool): If enabled, this will enable OIDC authentication
            flow directly from the application. Else, this will only enable the middleware
            to verify JWT received via Authorization header to
        client_id (str | None): Expected consumer for the token. Requestor (application) whose
            tokens are going to be accepted for this application.
            If `enable_oidc_flow`, this value will be used into the OIDC flow for authenticating
            this middleware against the IAM service to request tokens.
        client_secret (str | None): Client secret used into the OIDC flow for authenticating this
            middleware against the IAM service to request tokens. It is mandatory to provide
            it if `enable_oidc_flow` is enabled
    """

    OIDC_CONFIG_DEFAULT: str = (
        "https://auth.cern.ch/auth/realms/cern/.well-known/openid-configuration"
    )
    JWT_PUBLIC_KEY_URL: str = (
        "https://auth.cern.ch/auth/realms/cern/protocol/openid-connect/certs"
    )
    JWT_REGEX_PATTERN: str = (
        r"eyJ([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_=]+)\.([a-zA-Z0-9_\-\+\/=]*)"
    )

    def __init__(
        self,
        app: Flask,
        enable_oidc_flow: bool = bool(os.getenv("ENABLE_OIDC_FLOW")),
        client_id: str | None = os.getenv("CLIENT_ID"),
        client_secret: str | None = os.getenv("CLIENT_SECRET"),
    ):
        self.oidc_config: str = os.getenv(
            "REALM_OIDC_CONFIG", AuthenticationMiddleware.OIDC_CONFIG_DEFAULT
        )
        self.jwt_public_key_url: str = os.getenv(
            "REALM_PUBLIC_KEY_URL", AuthenticationMiddleware.JWT_PUBLIC_KEY_URL
        )
        self.jwt_regex_pattern: str = AuthenticationMiddleware.JWT_REGEX_PATTERN
        self.jwt_regex = re.compile(self.jwt_regex_pattern)
        self.client_id: str | None = client_id
        self.client_secret: str | None = client_secret
        self.enable_oidc_flow: bool = enable_oidc_flow

        # Verify client_id value is set properly
        if not self.client_id:
            client_id_error_msg: str = (
                "Client ID has not been set "
                f"Provided value: {self.client_id} "
                f"Type - {type(self.client_id)}"
            )
            raise ValueError(client_id_error_msg)

        # Verify client_password is provided if `enable_oidc_flow`
        if self.enable_oidc_flow and not self.client_secret:
            client_secret_error_msg: str = (
                "AuthenticationMiddleware is configured to handle "
                "OIDC flow directly but no client secret "
                "was provided "
                f"Client secret received: {self.client_secret} "
                f"Type - {type(self.client_secret)}"
            )
            raise ValueError(client_secret_error_msg)

        self.valid_audiences: list[str] = [self.client_id]
        self.app: Flask = self.__configure_session_cookie_security(app=app)
        self.jwk: jwt.PyJWK = self.__retrieve_jwk()

        # Enable OIDC flow if required
        if self.enable_oidc_flow:
            self.oauth_client: OAuth = self.__register_oauth_client()
            self.oauth_blueprint: Blueprint = self.__register_blueprint()

    def __auth(self) -> Response:
        """
        This endpoint starts the OIDC authentication flow against the OAuth 2.0 Authorization Server
        to request an access and refresh token.

        Returns:
            flask.Response: HTTP 302 response to redirect the user to the authorization server
                for login
        """
        redirect_uri: str = url_for("oauth.callback", _external=True)
        return self.oauth_client.cern.authorize_redirect(redirect_uri)

    def __callback(self) -> Response:
        """
        This endpoint handles the callback from the OAuth 2.0 Authorization Server and
        stores the access and refresh tokens inside a cookie handled by the Flask.
        Also, this endpoint redirects the user back to its original destination.

        Returns:
            flask.Response | werkzeug.wrappers.response.Response: HTTP 302 redirection
                to the original endpoint requested by the user. This also stores the
                session JWT into cookies to authorize future requests to resources
        Raises:
            HTTPException: If there is an error validating the access token provided by the
                authorization server. This step mainly prevents CSRF attacks
        """
        try:
            token = self.oauth_client.cern.authorize_access_token()
            session["token"] = {
                "access_token": token["access_token"],
                "refresh_token": token["refresh_token"],
            }
            original_destination: str = session.pop("next", default=url_for("/"))
            return redirect(original_destination)
        except Exception as auth_error:
            msg: str = f"Error validating access token - Details: {auth_error}"
            error: dict = {"msg": msg}
            response: Response = jsonify(error)
            response.status_code = 400
            logger.error(auth_error)
            raise HTTPException(
                description="Error validating access token", response=response
            ) from auth_error

    def __configure_session_cookie_security(self, app: Flask) -> Flask:
        """
        Restrict the access to the session cookie.
        A Flask session cookie is going to be used to store the JWT token to authenticate the user,
        and the next endpoint which the user is going to be redirected
        after a successful authentication.
        Based on Flask documentation, the session cookie is cryptographically
        signed when it is transmitted to the client web browser.
        For more information, please see:
        https://flask.palletsprojects.com/en/2.2.x/quickstart/?highlight=session#sessions

        Returns:
            Flask: Flask application with some cookie security policies configured
        """
        # Configure the session cookie
        app.config["SESSION_COOKIE_SAMESITE"] = "None"
        app.config["SESSION_COOKIE_HTTPONLY"] = True
        app.config["SESSION_COOKIE_SECURE"] = True
        return app

    def __register_blueprint(self) -> Blueprint:
        """
        Register a submodule (blueprint) inside the Flask application to
        include the authentication endpoint that handle OIDC authentication.
        The new submodule is registered under the /oauth2 url prefix.

        Returns:
            flask.Blueprint: Submodule which provides HTTP endpoints to handle OIDC authentication
                flow
        """
        oauth_blueprint = Blueprint("oauth", __name__)
        # Register views
        oauth_blueprint.add_url_rule(
            rule="/auth", endpoint="auth", view_func=self.__auth
        )
        oauth_blueprint.add_url_rule(
            rule="/callback", endpoint="callback", view_func=self.__callback
        )
        # Register OAuth submodule into the application
        self.app.register_blueprint(blueprint=oauth_blueprint, url_prefix="/oauth2")
        return oauth_blueprint

    def __register_oauth_client(self) -> OAuth:
        """
        Instantiates a OAuth 2.0 middleware into the Flask application
        to handle OIDC authentication flow. Configure the middleware
        to grab the standard configuration (from the well known endpoint)
        provided by authorization server (by default, from CERN SSO Authorization server)

        Returns:
            authlib.integrations.flask_client.OAuth: OAuth2 middleware
                to handle OIDC flow
        """
        # Set the client id and secret
        client_credentials: dict = {
            "CERN_CLIENT_ID": self.client_id,
            "CERN_CLIENT_SECRET": self.client_secret,
        }

        # Update the application to include this environment variables
        self.app.config.from_mapping(client_credentials)

        # Register CERN Realm
        oauth_client: OAuth = OAuth(app=self.app)
        oauth_client.register(
            name="cern",
            server_metadata_url=self.oidc_config,
            client_kwargs={
                "scope": "openid profile email",
            },
        )
        return oauth_client

    def __retrieve_jwk(self) -> jwt.PyJWK:
        """
        Retrieve the public key from the OAuth 2.0 authorization server to
        validate JWT access token.

        Returns:
            jwt.PyJWK: JSON Web Key to validate a provided JWT
        """
        jwks_client = jwt.PyJWKClient(self.jwt_public_key_url)
        return jwks_client.get_signing_keys()[0]

    def __token_to_user(self, decoded_token: dict) -> UserInfo:
        """
        Parse the user data available inside the JWT access token
        and return a user information (UserInfo) data object.

        Returns:
            UserInfo: User information retrieved from JWT
        """
        username: str = decoded_token.get("sub", "")
        roles: list[str] = decoded_token.get("cern_roles", [])
        email: str = decoded_token.get("email", username)
        given_name: str = decoded_token.get("given_name", "")
        family_name: str = decoded_token.get("family_name", "")
        fullname: str = decoded_token.get("name", "")

        return UserInfo(
            username=username,
            roles=roles,
            email=email,
            given_name=given_name,
            family_name=family_name,
            fullname=fullname,
        )

    def __decode_token(self, access_token: str) -> UserInfo | None:
        """
        Decodes a JWT access token and checks if the JWT is valid by using the authentication
        server JWK and if the token was requested for the current application
        (by checking its audience).

        Returns:
            None: If the access token provided does not match a JWT format
            UserInfo: User's information retrieved from the provided JWT if this is valid

        Raises:
            ExpiredSignatureError: If the JWT was request by the authorization server
                but it has expired
            HTTPException: HTTP 401 response (Unauthorized) if the JWT was not signed by
                the authorization server, or if it was requested for another application.
                This response is raised for the InvalidTokenError, for more details
                please see: https://pyjwt.readthedocs.io/en/latest/api.html#exceptions
        """
        jwt_raw_token = self.jwt_regex.search(access_token)
        if jwt_raw_token:
            raw_token = jwt_raw_token[0]
            try:
                decoded_token: dict = jwt.decode(
                    jwt=raw_token,
                    key=self.jwk.key,
                    audience=self.valid_audiences,
                    algorithms=["RS256"],
                )
                return self.__token_to_user(decoded_token)
            except ExpiredSignatureError as expired_error:
                logger.error(expired_error)
                raise expired_error
            except InvalidTokenError as token_error:
                msg: str = (
                    "The provided JWT token is invalid - " f"Details: {token_error}"
                )
                error: dict = {"error": msg}
                response: Response = jsonify(error)
                response.status_code = 401
                logger.error(token_error)
                raise HTTPException(description=msg, response=response) from token_error

        return None

    def __retrieve_token_from_session(
        self, flask_session: SessionMixin
    ) -> UserInfo | None:
        """
        Retrieves the access token from the Flask session cookie.
        If the access token is expired, both access and refresh tokens will be removed
        from the Flask session cookie, this will force the authentication flow against the
        authorization server.

        Returns:
            None: If it is required to start the authentication flow to the
                authorization server. This happens if there is no access token and refresh token
                available into the Flask session cookie or if the access token has expired
            UserInfo: User's information parsed from the JWT available inside the session cookie
        """
        session_cookie: dict | None = flask_session.get("token")
        if session_cookie:
            access_token: str | None = session_cookie.get("access_token", "")
            try:
                return (
                    self.__decode_token(access_token=access_token)
                    if access_token
                    else None
                )
            except ExpiredSignatureError as exp_error:
                # Current session has expired
                # Delete the current token and ask the auth server
                # to give you a new one
                logger.error(
                    "Session cookie has expired. Asking the auth server for a new one"
                )
                logger.error("Error: %s", exp_error)
                flask_session.pop("token")
                return None
        return None

    def __retrieve_token_from_request(self, request: Request) -> UserInfo | None:
        """
        Retrieves the JWT (access token) provided via HTTP Authorization header
        and checks that it is valid.

        Returns:
            None: If it is required to start the authentication flow to the
                authorization server. This happens if there is no access token
                provided via Authorization header or if the provided access token
                is expired
            UserInfo: User's information parsed from the JWT available inside the session cookie
        """
        access_token: str | None = request.headers.get("Authorization", "")
        if access_token:
            try:
                return self.__decode_token(access_token=access_token)
            except ExpiredSignatureError:
                return None
        return None

    def authenticate(
        self, request: Request, flask_session: SessionMixin
    ) -> Response | None:
        """
        Checks, for every HTTP request, if the HTTP request is already authenticated
        or if it requires authentication by looking for a valid JWT provided
        via HTTP Authorization header or into Flask session cookie.
        If the JWT is valid, the user information available inside of it will be parsed and stored
        into the Flask session cookie under the key "user".

        If the provided JWT is not valid and the middleware has been configured to handle OIDC flow
        by itself (`enable_oidc_flow`), this will return a HTTP 302 response to start an interactive
        authentication flow. Else, a HTTP 401 will be raised asking for a JWT to be provided into
        the Authorization header.

        This middleware and its `authenticate` method are intended to be used inside @before_request
        Flask middleware function. For more details, please see:
        https://flask.palletsprojects.com/en/2.2.x/api/?highlight=environ#flask.Flask.before_request

        Args:
            request (flask.Request): HTTP request to check if it is authenticated
            flask_session (flask.SessionMixin): Flask session for the current request

        Returns:
            None: If the HTTP request has been succesfully authenticated and the requested
                endpoint can be consumed.
            flask.Response | werkzeug.wrappers.response.Response: HTTP 302 redirection
                to the OIDC authentication endpoint if `enable_oidc_flow` and
                it is required to start the authentication flow
        Raises:
            HTTPException: A HTTP 401 response if the middleware is not set to handle OIDC
                authentication flow by itself and no JWT was provided via HTTP Authorization header.
        """
        valid_auth_endpoints = ("oauth.auth", "oauth.callback")
        if request.endpoint in valid_auth_endpoints:
            # The user is performing an authentication process
            # This is usefull when you require to install the middleware
            # on the top of the Flask application. @before_request function
            # is called before any view, therefore, this could lead to infinite
            # redirect loops.
            return None

        user_data: UserInfo | None = None
        user_data = self.__retrieve_token_from_request(request=request)
        if user_data:
            flask_session["user"] = user_data
            return None

        # Check if the middleware handles OIDC flow. If so, check the Flask session cookie
        if self.enable_oidc_flow:
            user_data = self.__retrieve_token_from_session(flask_session=flask_session)
            if user_data:
                flask_session["user"] = user_data
                return None

            # JWT available into Flask session cookie is invalid
            # Start the authentication flow
            original_destination: str = request.url
            flask_session["next"] = original_destination
            redirect_uri: str = url_for(endpoint="oauth.auth")
            return redirect(location=redirect_uri)

        msg: str = (
            "Please provide a JWT via Authorization header. "
            "If a JWT was provided, please provide a JWT "
            "that is valid because the current is expired"
        )
        response: Response = jsonify({"msg": msg})
        response.status_code = 401
        raise HTTPException(
            description="JWT checked via Authorization header is invalid",
            response=response,
        )
