from os.path import isfile
from validator import Validator
from passwd import Passwd
from leak_check import LeakCheck

class InputFormer:
    def __init__(self, str_or_file) -> None:
        self.input_data = str_or_file

    def get_data(self):
        if isfile(self.input_data):
            with open(self.input_data, 'r') as passwd_file:
                for passwd in passwd_file:
                    yield passwd
        else:
            yield self.input_data

        return None

class PasswordChecker:
    def __init__(self, passwords : str) -> None:
        self.passwords = InputFormer(passwords)
        self.check_valid_and_leak()

    def check_valid_and_leak(self):
        for password in self.passwords.get_data():
            passwd = Passwd(password.strip())
            if Validator(passwd):
                if LeakCheck(passwd):
                    print('is ok')
                else:
                    print('leak')
            else:
                print('not valid')


if __name__ == '__main__':
    input_data = input("Give me password's file or single password to check: ")
    PasswordChecker(input_data)
