from os.path import isfile
from sys import argv
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
    def __init__(self, passwords : str, valid_exc : bool = False) -> None:
        self.passwords = InputFormer(passwords)
        self.valic_exc = valid_exc

    def check_valid_and_leak(self):
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
            except Exception as err:
                yield passwd.raw_pass, err

class Fuse:
    def __init__(self) -> None:
        self.passwd_output = False
        self.log = False

    def check_start_parameters(self):
        if '-log' in argv:
            self.log = True
        if '-output' in argv:
            self.passwd_output = True
        for arg in argv[1:]:
            if isfile(arg):
                return arg
        return None

    def get_data_from_user(self):
        input_data = input("Give me password's file or single password to check: ")
        return input_data

    def get_parameters_from_user(self):
        user_input = None
        while not user_input in ['Y','y','N','n']:
            user_input = input('Do you wont make output file with safety passwords? (y/n): ')
            if user_input.lower() == 'y':
                    self.passwd_output = True
        user_input = None
        while not user_input in ['Y','y','N','n']:
            user_input = input('Turn on Logs? (y/n): ')
            if user_input.lower() == 'y':
                    self.log = True

    def check_password_safety(self, password_content):
        for data, message in PasswordChecker(password_content, self.log).check_valid_and_leak():
            if self.log:
                self.cerate_log((data, message))
            if self.passwd_output:
                self.make_output_file(data)
            yield data, message

    def cerate_log(self, log_data):
        pass

    def make_output_file(self, safety_password):
        with open('out.txt', 'w+') as output_file:
            output_file.write(safety_password)


if __name__ == '__main__':
    fuse = Fuse()
    input_data = None
    if len(argv) > 1:
        input_data = fuse.check_start_parameters()
    else:
        fuse.get_parameters_from_user()
    if not input_data:
        input_data = fuse.get_data_from_user()
    fuse.check_password_safety(input_data)
