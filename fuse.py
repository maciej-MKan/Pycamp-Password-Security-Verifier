#!/usr/bin/env python
# -*- encoding: utf-8 -*-
# -*- coding: utf-8 -*-
"""script to check password safety
run:
fuse.py <file> <-log> <-output>
file : file name with passwords (see pass.example)
-log : to create log file
-output : to create file with safety passwords
if you run the program directly, it will ask for parameters"""

import logging
from os import path
from sys import argv
from datetime import datetime

from validator import Validator, VALIDATOR_EXCEPTIONS as ValExcept
from passwd import Passwd
from leak_check import LeakCheck, ServiceUnavailable

#pylint: disable=too-few-public-methods
#pylint: disable=logging-fstring-interpolation

class InputFormer:
    """Checks whether the input data is a file or str and modifies it accordingly"""
    def __init__(self, str_or_file) -> None:
        self.input_data = str_or_file

    def get_data(self) -> str:
        """generate strings from a file or given word

        Yields:
            str: single password
        """
        if path.isfile(self.input_data):
            with open(self.input_data, 'r', encoding='utf-8') as passwd_file:
                for passwd in passwd_file:
                    yield passwd
        else:
            yield self.input_data

class PasswordChecker:
    """validates passwords

    Args:
        passwords (str): file with passwords or single password
        valid_exc (bool): whether the validator should throw exceptions
    """
    def __init__(self, passwords : str, valid_exc : bool = False) -> None:
        self.passwords = InputFormer(passwords)
        self.valic_exc = valid_exc

    def check_valid_and_leak(self):
        """call validators in the appropriate configuration"""
        safe = None
        for password in self.passwords.get_data():
            passwd = Passwd(password.strip())
            try:
                if Validator(passwd, raise_exceptions = self.valic_exc):
                    if LeakCheck(passwd):
                        safe = 'is safe'
                    else:
                        safe = 'not safe - leak'
                else:
                    safe = 'not valid'
                yield passwd.raw_pass, safe
            except ValExcept as err:
                yield passwd.raw_pass, str(err)

class Fuse:
    """main class with program logic"""
    def __init__(self) -> None:
        self.passwd_output = False
        self.log = False

    def passwd_output_enable(self):
        """enables the saving of valid passwords to the output file"""
        self.passwd_output = True
        if path.isfile('out.txt'):
            logging.warning(
                f'{datetime.now()} - out.txt exists. The data will be appended to the file.')
            with open('out.txt', 'a', encoding='utf-8') as file:
                file.write(f'\n{datetime.now()}\n')

    def check_start_parameters(self):
        """checks if the script was run with parameters"""
        if '-log' in argv:
            self.create_log('Looging enabled by start parameter')
        if '-output' in argv:
            self.passwd_output_enable()
        for arg in argv[1:]:
            if path.isfile(arg):
                return arg
        return None

    @staticmethod
    def get_data_from_user():
        """prompts the user for passwords"""
        user_data = input("Give me password's file or single password to check: ")
        return user_data

    def get_parameters_from_user(self):
        """prompts the user for parameters(log and output files)"""
        user_input = None
        while not user_input in ['Y','y','N','n']:
            user_input = input('Turn on Logs? (y/n): ')
            if user_input.lower() == 'y':
                self.create_log('Looging enabled by user')
        user_input = None
        while not user_input in ['Y','y','N','n']:
            user_input = input('Do you wont make output file with safety passwords? (y/n): ')
            if user_input.lower() == 'y':
                self.passwd_output_enable()

    def check_password_safety(self, password_content):
        """invokes a password check class, receives responses from it, creates a log if enabled

        Args:
            password_content (str): input data from user

        Yields:
            data (str): password checked, message (str): the result of the check
            ecx (str): exception from validator
        """
        try:
            for data, message in PasswordChecker(password_content, self.log).check_valid_and_leak():
                if self.log:
                    logging.info(f'{datetime.now()} - {data} - {message}')
                if self.passwd_output and 'is safe' in str(message):
                    self.make_output_file(data)
                yield data, message
        except ServiceUnavailable as exc:
            logging.error(f'{datetime.now()} - {exc}')
            yield None, f'{exc}. Try later'

    def create_log(self, log_data):
        """creating log"""
        self.log = True
        logging.basicConfig(filename='fuse.log', level=logging.INFO, filemode='w')
        logging.info(f'{datetime.now()} - {log_data}')

    def make_output_file(self, safety_password):
        """creating output file"""
        with open('out.txt', 'a', encoding='utf-8') as output_file:
            if self.log:
                logging.info(f'{datetime.now()} - writing password to out.txt')
            output_file.write(f'{safety_password}\n')

    def __del__(self):
        if self.log:
            logging.info(f'{datetime.now()} - job done')


if __name__ == '__main__':
    fuse = Fuse()
    try:
        if len(argv) > 1:
            input_data = fuse.check_start_parameters()
        else:
            fuse.get_parameters_from_user()
            input_data = fuse.get_data_from_user()
        for i in fuse.check_password_safety(input_data):
            print(i)
        del fuse
    except TypeError:
        print('bad argv')
