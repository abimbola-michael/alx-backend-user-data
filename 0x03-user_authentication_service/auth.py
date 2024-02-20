#!/usr/bin/env python3
"""
Auth module
"""
from uuid import uuid4
import bcrypt
from db import DB
from user import User
from typing import Optional
from sqlalchemy.orm.exc import NoResultFound


def _hash_password(password: str) -> bytes:
    """
    Hash a password
    """
    encoded = password.encode("utf-8")
    return bcrypt.hashpw(encoded, bcrypt.gensalt())


def _generate_uuid() -> str:
    """
    Generate a UUID
    """
    return str(uuid4())


class Auth:
    """Auth class to interact with the authentication database.
    """

    def __init__(self):
        """Initialize a new Auth instance
        """
        self._db = DB()

    def register_user(self, email: str, password: str) -> Optional[User]:
        """
        Register a user
        """
        try:
            self._db.find_user_by(email=email)
        except NoResultFound:
            password = _hash_password(password).decode("utf-8")
            return self._db.add_user(email, password)
        else:
            raise ValueError(f"User {email} already exists")

    def valid_login(self, email: str, password: str) -> bool:
        """
        Validate a user's login
        """
        try:
            user = self._db.find_user_by(email=email)
            encoded = password.encode("utf-8")
            return bcrypt.checkpw(encoded, user.hashed_password)
        except NoResultFound:
            return False

    def create_session(self, email: str) -> str:
        """
        Create a session
        """
        try:
            user = self._db.find_user_by(email=email)
            session_id = _generate_uuid()
            user.session_id = session_id
            self._db._session.commit()
            return session_id
        except NoResultFound:
            return None

    def get_user_from_session_id(self, session_id: str) -> User:
        """
        Get a user from a session ID
        """
        try:
            return self._db.find_user_by(session_id=session_id)
        except NoResultFound:
            return None

    def destroy_session(self, user_id: int) -> None:
        """
        Destroy a session
        """
        try:
            user = self._db.find_user_by(id=user_id)
            user.session_id = None
            self._db._session.commit()
        except NoResultFound:
            pass

    def get_reset_password_token(self, email: str) -> str:
        """
        Get a reset password token
        """
        try:
            user = self._db.find_user_by(email=email)
            reset_token = _generate_uuid()
            user.reset_token = reset_token
            self._db._session.commit()
        except NoResultFound:
            raise ValueError

    def update_password(self, reset_token: str, password: str) -> None:
        """
        Update password
        """
        try:
            user = self._db.find_user_by(reset_token=reset_token)
            password = _hash_password(password).decode("utf-8")
            user.hashed_password = password
            user.reset_token = None
            return None
        except NoResultFound:
            raise ValueError
