"""tests for passwd.py"""

from passwd import Passwd

def test_generate_sha1():
    """test sha1 generating"""
    test_passord = Passwd('test')
    assert test_passord.hash_pass == 'a94a8fe5ccb19ba61c4c0873d391e987982fbbd3'

def test_convert_bytes():
    """test converting string to bytes"""
    test_password = Passwd('test')
    assert test_password.byte_pass == b'test'
