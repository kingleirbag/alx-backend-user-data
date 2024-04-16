#!/usr/bin/env python3
""" Module Basic_auth for user authentication
"""
from typing import TypeVar, Tuple
from base64 import b64decode, decode
from api.v1.auth.auth import Auth
from models.user import User
import base64


class BasicAuth(Auth):
    """- Methods for basic authorization
    - inherits from Auth
    Args:
        Auth (class): Parent authentication class
    """
    def extract_base64_authorization_header(self, auth_header: str) -> str:
        """returns the Base64 part of the Authorization header
        for a Basic Authentication
        Args:
            authorization_header (str): auth_header
        Returns:
            str: base64 part of header
        """
        if auth_header is None or not isinstance(auth_header, str):
            return None
        if 'Basic ' not in auth_header:
            return None
        return auth_header[6:]

    def decode_base64_authorization_header(self, b64_auth_header: str) -> str:
        """Returns the decoded value of a Base64 string
        Args:
            base64_authorization_header (str): base64 auth header
        Returns:
            str: decoded value of base64 string
        """
        if b64_auth_header is None or not isinstance(b64_auth_header, str):
            return None
        try:
            b64 = base64.b64decode(b64_auth_header)
            b64_decode = b64.decode('utf-8')
        except Exception:
            return None
        return b64_decode

    def extract_user_credentials(
            self, decoded_b64_auth_header: str) -> (str, str):
        """extracts user email and password from the Base64 decoded value.
        Args:
            self (obj): Basic Auth instance
            decoded_base64_authorization_header (str): auth header
        """
        if decoded_b64_auth_header is None or not isinstance(
                decoded_b64_auth_header, str) \
           or ':' not in decoded_b64_auth_header:
            return (None, None)
        return decoded_b64_auth_header.split(':', 1)

    def user_object_from_credentials(
            self, user_email: str, user_pwd: str) -> TypeVar('User'):
        """Returns user object from credentials
        Args:
            self (_type_): Basic auth instance
            user_email(str): user email
            user_pwd(str): user pwd
        """
        if user_email is None or not isinstance(
                user_email, str) or user_pwd is None or not isinstance(
                    user_pwd, str):
            return None
        try:
            users = User.search({'email': user_email})
        except Exception:
            return None
        for user in users:
            if user.is_valid_password(user_pwd):
                return user
            return None

    def current_user(self, request=None) -> TypeVar('User'):
        """ gets current user """
        auth_header = self.authorization_header(request)
        if not auth_header:
            return None
        extract_base64 = self.extract_base64_authorization_header(auth_header)
        decode_base64 = self.decode_base64_authorization_header(extract_base64)
        user_credentials = self.extract_user_credentials(decode_base64)
        user_email = user_credentials[0]
        user_password = user_credentials[1]
        user_credentials = self.user_object_from_credentials(
            user_email, user_password)
        return user_credentials
