"""checks if the password meets the security requirements"""
from passwd import Passwd

class TooShort(Exception):
    """exception when password is less than 8 characters long"""

class NoUpperCase(Exception):
    """exception when password does not have uppercase characters"""

class NoLowerCase(Exception):
    """exception when password does not have lowercase characters"""

class NoNumber(Exception):
    """exception when password has no numbers"""

class NoSpecjal(Exception):
    """exception when password does not have specjal characters"""

class Validator():
    """_summary_
    """

    def __init__(self, passwd : Passwd) -> None:
        self._passwd = passwd.raw_pass
        self.check_valid()

    def check_valid(self) -> bool:
        """checks if the password is> 8 characters long,
        has lowercase, uppercase and special characters"""

        range_specjals = r'! " # $ % &  ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _` { | }' + r"'"

        if len(self._passwd) < 8:
            raise TooShort('the password is less than 8 characters long')

        if not [upper_case for upper_case in self._passwd if upper_case.isupper()]:
            raise NoUpperCase('the password does not have uppercases')

        if not [lower_case for lower_case in self._passwd if lower_case.islower()]:
            raise NoLowerCase('the password does not have lowercases')

        if not [number for number in self._passwd if number.isnumeric()]:
            raise NoNumber('the password does not have numbers')

        if not [specjal for specjal in self._passwd if specjal in range_specjals]:
            raise NoSpecjal('the password does not have specjal characters')

        return True
