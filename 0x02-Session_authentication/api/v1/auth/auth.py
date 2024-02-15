#!/usr/bin/env python3
"""
Auth module
"""
from flask import request, jsonify, abort
from typing import List, TypeVar
from os import getenv


class Auth:
    """
    Auth class
    """

    def require_auth(self, path: str, excluded_paths: List[str]) -> bool:
        """
        require_auth method
        """
        if not path or not excluded_paths or excluded_paths == []:
            return True

        if path[-1] != '/':
            path += '/'

        if path not in excluded_paths:
            return True

        return False

    def authorization_header(self, request=None) -> str:
        """
        authorization_header method
        """
        if request is None or "Authorization" not in request.headers:
            return None

        return request.headers["Authorization"]

    def current_user(self, request=None) -> TypeVar('User'):
        """
        current_user method
        """
        return None

    def session_cookie(self, request=None):
        """
        session_cookie method
        """
        if request is None:
            return None
        session_name = getenv("SESSION_NAME")
        return request.cookies.get(session_name)
