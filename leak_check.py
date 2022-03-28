"""check if the password is leaked"""
from time import sleep
import requests
from passwd import Passwd

class ServiceUnavailable(Exception):
    """exception when api pwned is no avaible"""

class LeakChecker:
    """password leak check mechanism"""

    def __init__(self, passwd : Passwd ) -> None:
        self.password_prefix = passwd.hash_pass[:5]
        self.password_sufix = passwd.hash_pass[5:]
        self._api_url = 'https://api.pwnedpasswords.com/range/'
        self._test_prefix = '12345'
        self.check_password_save()

    def check_connection(self, tries : int) -> bool:
        """check connection wiht api

        Args:
            trys (int): number of tries

        Returns:
            bool: whether connection with api is avaible
        """
        with requests.get(self._api_url + self._test_prefix) as test_request:
            if test_request.status_code != 200 and tries > 1:
                sleep(5)
                self.check_connection(tries - 1)
            return test_request.status_code == 200

    def check_password_save(self) -> bool:
        """main method to check for password leakage

        Raises:
            ServiceUnavailable: exception when api is not avaible

        Returns:
            bool: whether the password is secure
        """
        password_security = False
        if not self.check_connection(2):
            raise ServiceUnavailable('api pwned is no avaible')

        with requests.get(self._api_url + self.password_prefix) as  api_request:
            if api_request.text:
                api_request_lines = api_request.text.splitlines()
                if self.password_sufix.upper() in\
                [api_request_line.split(':')[0] for api_request_line in api_request_lines]:
                    password_security = False
                else:
                    password_security = True
            else:
                password_security = True

        return password_security
