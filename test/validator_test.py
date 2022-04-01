"""tests for validator.py"""

from pytest import raises
from passwd import Passwd
from validator import Validator, TooShort, NoUpperCase, NoLowerCase, NoSpecjal, NoNumber

def test_password_too_short():
    """test exception when password is too short"""
    test_password = Passwd('aA1!')

    with raises(TooShort) as exctinfo:
        test_validator = Validator(test_password, raise_exceptions=True)
        bool(test_validator)
    assert 'password is less' in str(exctinfo.value)

def test_password_no_upper():
    """test exception when password has no uppers"""
    test_password = Passwd('aaabbb1!')

    with raises(NoUpperCase) as exctinfo:
        test_validator = Validator(test_password, raise_exceptions=True)
        bool(test_validator)
    assert 'not have enough uppercases' in str(exctinfo.value)

def test_password_no_lower():
    """test exception when password has no lower"""
    test_password = Passwd('AAABBB1!')

    with raises(NoLowerCase) as exctinfo:
        test_validator = Validator(test_password, raise_exceptions=True)
        bool(test_validator)
    assert 'not have enough lowercases' in str(exctinfo.value)

def test_password_no_numbers():
    """test exception when password has no numbers"""
    test_password = Passwd('aaabbbC!')

    with raises(NoNumber) as exctinfo:
        test_validator = Validator(test_password, raise_exceptions=True)
        bool(test_validator)
    assert 'not have enough numbers' in str(exctinfo.value)

def test_password_specjals():
    """test exception when password has no specjal cases"""
    test_password = Passwd('aaabbbC1')

    with raises(NoSpecjal) as exctinfo:
        test_validator = Validator(test_password, raise_exceptions=True)
        bool(test_validator)
    assert 'not have enough specjal' in str(exctinfo.value)

def test_password_correct():
    """test correct password"""
    test_password = Passwd('aaabbC1!')

    test_validator = Validator(test_password)

    assert test_validator

def test_password_correct_fail():
    """test not correct password"""
    test_password = Passwd('')

    test_validator = Validator(test_password)

    assert not test_validator

def test_password_wo_validators():
    """test dummy password validator"""
    test_password = Passwd('')

    test_validator = Validator(
        test_password, lenght=False, uppers=False, lowers=False, numbers=False, specjals=False
        )

    assert test_validator
