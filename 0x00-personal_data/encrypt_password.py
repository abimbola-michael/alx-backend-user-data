#!/usr/bin/env python3
"""Encrypting passwords"""
import bcrypt


def hash_password(password: str) -> bytes:
    """
    function that expects one string argument name
    password and returns a salted, hashed password,
    which is a byte string.
    """
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt())


def is_valid(hashed_password: bytes, password: str) -> bool:
    """
    function that uses bcrypt to validate that the provided
    password matches the hashed password.
    """
    return bcrypt.checkpw(password.encode(), hashed_password)
