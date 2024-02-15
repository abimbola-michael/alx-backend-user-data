#!/usr/bin/env python3
"""
BasicAuth module
"""
from api.v1.auth.auth import Auth
import base64
from typing import TypeVar
from models.user import User


class BasicAuth(Auth):
    """
    BasicAuth class
    """

    def extract_base64_authorization_header(
            self, authorization_header: str
    ) -> str:
        """
        returns the Base64 part of the Authorization
        header for a Basic Authentication:
        """
        if authorization_header is None or type(
            authorization_header
        ) != str:
            return None

        if not authorization_header.startswith("Basic"):
            return None
        return authorization_header[6:]

    def decode_base64_authorization_header(
            self, base64_authorization_header: str
    ) -> str:
        """
        returns the decoded value of a Base64 string
        """
        if base64_authorization_header is None or type(
            base64_authorization_header
        ) != str:
            return None

        try:
            encoded = base64_authorization_header.encode("utf-8")
            decoded = base64.b64decode(encoded)
            return decoded.decode("utf-8")
        except Exception:
            return None

    def extract_user_credentials(
            self, decoded_base64_authorization_header: str
    ) -> (str, str):
        """
         that returns the user email and password from
         the Base64 decoded value.
        """
        if decoded_base64_authorization_header is None or type(
            decoded_base64_authorization_header
        ) != str:
            return (None, None)
        if ":" not in decoded_base64_authorization_header:
            return (None, None)

        values = decoded_base64_authorization_header.split(":", 1)
        return (values[0], values[1])

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str
    ) -> TypeVar('User'):
        """
        returns the User instance based on his email and password.
        """
        if user_email is None or type(user_email) != str:
            return None
        if user_pwd is None or type(user_pwd) != str:
            return None

        try:
            users = User.search({"email": user_email})
            if not users:
                return None
            for user in users:
                if user.is_valid_password(user_pwd):
                    return user
            return None
        except Exception:
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """
        that overloads Auth and retrieves the User
        instance for a request:
        """
        header = self.authorization_header(request)
        if header:
            auth_header = self.extract_base64_authorization_header(header)
            if auth_header:
                decoded = self.decode_base64_authorization_header(auth_header)
                if decoded:
                    email, password = self.extract_user_credentials(decoded)
                    if email and password:
                        return self.user_object_from_credentials(
                            email, password
                        )
