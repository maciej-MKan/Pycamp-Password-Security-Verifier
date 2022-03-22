"""tests for validator.py"""

from passwd import Passwd
from validator import Validator, TooShort, NoUpperCase, NoLowerCase, NoSpecjal, NoNumber

def test_password_too_short():
    """test exception when password is too short"""
    test_password = Passwd('aA1!')
    try:
        _ = Validator(test_password)
    except TooShort as err:
        assert err
    except (NoUpperCase, NoLowerCase, NoSpecjal, NoNumber) as wrong_err:
        assert not wrong_err

def test_password_no_upper():
    """test exception when password has no uppers"""
    test_password = Passwd('aaabbb1!')
    try:
        _ = Validator(test_password)
    except NoUpperCase as err:
        assert err
    except (TooShort, NoLowerCase, NoSpecjal, NoNumber) as wrong_err:
        assert not wrong_err

def test_password_no_lower():
    """test exception when password has no lower"""
    test_password = Passwd('AAABBB1!')
    try:
        _ = Validator(test_password)
    except NoLowerCase as err:
        assert err
    except (TooShort, NoUpperCase, NoSpecjal, NoNumber) as wrong_err:
        assert not wrong_err

def test_password_no_numbers():
    """test exception when password has no numbers"""
    test_password = Passwd('aaabbbC!')
    try:
        _ = Validator(test_password)
    except NoNumber as err:
        assert err
    except (TooShort, NoLowerCase, NoSpecjal, NoUpperCase) as wrong_err:
        assert not wrong_err

def test_password_specjals():
    """test exception when password has no specjal cases"""
    test_password = Passwd('aaabbbC1')
    try:
        _ = Validator(test_password)
    except NoSpecjal as err:
        assert err
    except (TooShort, NoLowerCase, NoUpperCase, NoNumber) as wrong_err:
        assert not wrong_err

def test_password_correct():
    """test correct password"""
    test_password = Passwd('aaabbC1!')
    try:
        test_validator = Validator(test_password)
    except (TooShort, NoLowerCase, NoUpperCase, NoSpecjal, NoNumber) as wrong_err:
        assert not wrong_err
        assert test_validator
