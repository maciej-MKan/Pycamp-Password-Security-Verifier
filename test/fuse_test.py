"""tests for fuse.py"""

from unittest.mock import patch, mock_open
from fuse import Fuse, InputFormer, PasswordChecker
from validator import Validator
from leak_check import LeakCheck

TEST_FILE_DATA =\
"""line1
line2
line3
"""

@patch('builtins.open', new_callable=mock_open, read_data=TEST_FILE_DATA)
@patch('os.path.isfile')
def test_input_former_file(mock_isfile, mock_file):
    """test for InputFormer with file"""

    test_content = ''
    mock_isfile.return_value = True
    test_former = InputFormer('test_file')

    for content in test_former.get_data():
        test_content += content

    mock_isfile.assert_called_with('test_file')
    mock_file.assert_called_with('test_file', 'r', encoding='utf-8')
    assert test_content == TEST_FILE_DATA

@patch('os.path.isfile')
def test_input_former_str(mock_isfile):
    """test for InputFormer with str"""

    test_content = ''
    mock_isfile.return_value = False
    test_former = InputFormer('test_string')

    for content in test_former.get_data():
        test_content += content

    mock_isfile.assert_called_with('test_string')
    assert test_content == 'test_string'

@patch.object(LeakCheck, '__bool__')
@patch.object(Validator, '__bool__')
def test_check_valid_and_leak_wo_exc(mock_validator, mock_leak_check):
    """test PasswordChecker called witch out to return exceptions"""

    mock_validator.return_value = True
    mock_leak_check.return_value = True
    test_pw_checker = PasswordChecker('TestPW1#')

    for content in test_pw_checker.check_valid_and_leak():
        test_content = content

    mock_leak_check.assert_called()
    mock_validator.assert_called()
    assert test_content == ('TestPW1#', 'is safe')

@patch.object(LeakCheck, '__bool__')
def test_check_valid_and_leak_w_exc(mock_leak_check):
    """test PasswordChecker called with to return exceptions"""

    mock_leak_check.return_value = True
    test_pw_checker = PasswordChecker('TESTPW1#', valid_exc= True)

    for content in test_pw_checker.check_valid_and_leak():
        test_content = content

    mock_leak_check.assert_not_called()
    assert test_content ==\
        ('TESTPW1#', 'the password does not have enough lowercases')