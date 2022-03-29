"""tests for validator.py"""

import pytest
from passwd import Passwd
from leak_check import LeakCheck, ServiceUnavailable

TEST_LEAK_CHECK = LeakCheck(Passwd('test'))
TEST_URL = 'https://api.pwnedpasswords.com/range/a94a8'
#pylint: disable = protected-access
API_URL = TEST_LEAK_CHECK._api_url
TEST_RESPONSE =\
'''fe5ccb19ba61c4c0873d391e987982fbbd3:14
ff95277653f5b55ddd50f1dce513697d112:1'''.upper() +\
'''0363BABE2E41C7A2D7C4E58D392BBE15BB5:2
036B18487D9B1B0E334B31508912ABC7F08:1
036E70D41244E78CC1F94397CE7EF36DC00:1
03ECD7302EDC571D9F2D43848F045743D9E:6
04389FA67A077D995E613D4F326BB2A409B:2
04D07D84D6474B686D5DD5F5C72A729C43C:3
051CDB44536AB05FC8F3648731DBE75E9CF:1
054555A079E6C52256D15651C2A6663DDB9:3
05A7177A60AB6D2D0889FD08B6DFA6029FC:4
05AA32A1F74FD10E787DAD1EF61A399C2C1:1
05ED8B82BC639347C1509E9FAC64AA2D4FD:2
06A1A3683C2CF4C9E91415A1272857D216D:2
083536B05F8D77476B109A31B4FF50FC5E5:3
08597FCF86893DE61DFD7CA71D1F14D2391:8'''


def test_check_connection(requests_mock):
    """test connection with api check"""
    requests_mock.get(TEST_URL, text = TEST_RESPONSE, status_code = 200)

    assert TEST_LEAK_CHECK.check_connection(2)

def test_check_connection_fail(requests_mock):
    """test exception when connection with api is fail"""
    with pytest.raises(ServiceUnavailable) as exctinfo:
        requests_mock.get(TEST_URL, text = TEST_RESPONSE, status_code = 404)
        TEST_LEAK_CHECK.check_password_safe()

    assert 'no avaible' in str(exctinfo.value)

def test_check_password_safe(requests_mock):
    """test response when password is safe"""
    requests_mock.get(TEST_URL, text = TEST_RESPONSE, status_code = 200)
    requests_mock.get(API_URL+'be6c3', text = TEST_RESPONSE, status_code = 200)
    safe_leak_checker = LeakCheck(Passwd('safety'))
    assert safe_leak_checker

def test_check_password_safe_fail(requests_mock):
    """test response when password is not safe"""
    requests_mock.get(TEST_URL, text = TEST_RESPONSE, status_code = 200)
    requests_mock.get(API_URL+'3d7c9', text = TEST_RESPONSE, status_code = 200)
    not_safe_leak_checker = LeakCheck(Passwd('not_safety'))
    assert not not_safe_leak_checker
