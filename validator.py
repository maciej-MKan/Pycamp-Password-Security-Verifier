#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# -*- coding: utf-8 -*-
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

VALIDATOR_EXCEPTIONS = (TooShort, NoUpperCase, NoLowerCase, NoNumber, NoSpecjal)

class Validator():
    """_summary_
    """

    def __init__(
        self, passwd : Passwd,
        lenght : bool = True, min_len : int = 8,
        uppers : bool = True, min_uppers : int = 1,
        lowers : bool = True, min_lowers : int = 1,
        numbers : bool = True, min_numbers : int = 1,
        specjals : bool = True, min_specjals : int = 1,
        raise_exceptions : bool = False
        ) -> None:

        self._passwd = passwd.raw_pass
        self.lenght = lenght
        self.min_len = min_len
        self.uppers = uppers
        self.min_uppers = min_uppers
        self.lowers = lowers
        self.min_lowers = min_lowers
        self.numbers = numbers
        self.min_numbers = min_numbers
        self.specjals = specjals
        self.min_specjals = min_specjals
        self.raise_exceptions = raise_exceptions

    def __bool__(self) -> bool:
        return self.check_valid()

    def check_valid(self) -> bool:
        """checks if the password is > minimum lenght characters long"""
        checks_list = [
            self.check_len(), self.check_uppers(),
            self.check_lowers(), self.check_numbers(),
            self.check_specjals()
            ]

        return all(checks_list)

    def check_len(self) -> bool:
        """checks if the password is > minimum lenght characters long"""
        if not self.lenght:
            return True
        is_valid = len(self._passwd) >= self.min_len
        if not is_valid and self.raise_exceptions:
            raise TooShort(f'the password is less than {self.min_len} characters long')
        return is_valid

    def check_uppers(self) -> bool:
        """checks if the password have enough uppercase"""
        if not self.uppers:
            return True
        valid_list = [True for upper_case in self._passwd if upper_case.isupper()]
        is_valid = any(valid_list) and len(valid_list) >= self.min_uppers
        if not is_valid and self.raise_exceptions:
            raise NoUpperCase('the password does not have enough uppercases')
        return is_valid

    def check_lowers(self) -> bool:
        """checks if the password have enough lowercase"""
        if not self.lowers:
            return True
        valid_list = [True for lower_case in self._passwd if lower_case.islower()]
        is_valid = any(valid_list) and len(valid_list) >= self.min_lowers
        if not is_valid and self.raise_exceptions:
            raise NoLowerCase('the password does not have enough lowercases')
        return is_valid

    def check_numbers(self) -> bool:
        """checks if the password have enough numbers"""
        if not self.numbers:
            return True
        valid_list = [True for number in self._passwd if number.isnumeric()]
        is_valid = any(valid_list) and len(valid_list) >= self.min_numbers
        if not is_valid and self.raise_exceptions:
            raise NoNumber('the password does not have enough numbers')
        return is_valid

    def check_specjals(self) -> bool:
        """checks if the password have enough special characters"""
        range_specjals = r'! " # $ % &  ( ) * + , - . / : ; < = > ? @ [ \ ] ^ _` { | }' + r"'"

        if not self.specjals:
            return True
        valid_list = [True for specjal in self._passwd if specjal in range_specjals]
        is_valid = any(valid_list) and len(valid_list) >= self.min_specjals
        if not is_valid and self.raise_exceptions:
            raise NoSpecjal('the password does not have enough specjal characters')
        return is_valid
