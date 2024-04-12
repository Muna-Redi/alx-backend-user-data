#!/usr/bin/env python3
""" password encryption """
import bcrypt


def hash_password(password: str) -> bytes:
    """ This byte string of a  salted, _hashed password"""
    encryption = password.encode()
    p_hashed = bcrypt.hashpw(encryption, bcrypt.gensalt())

    return p_hashed


def is_valid(hashed_password: bytes, password: str) -> bool:
    """ checks the given password matches the hashed password """
    valid = False
    encryption = password.encode()
    if bcrypt.checkpw(encryption, hashed_password):
        valid = True
    return valid
