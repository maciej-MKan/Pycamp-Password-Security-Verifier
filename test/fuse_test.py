"""tests for fuse.py"""

from cgi import test
from sys import argv
from unittest import mock
from unittest.mock import patch, mock_open
from fuse import Fuse, InputFormer, PasswordChecker
from validator import Validator
from leak_check import LeakCheck


TEST_FILE_DATA =\
"""line1
line2
line3
"""

def answer_generator():
    for i in ['Y', 'N']:
        yield i

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

@patch('os.path.isfile')
@patch.object(Fuse, 'cerate_log')
@patch.object(Fuse, 'passwd_output_enable')
def test_check_start_parameters_w_all_argv(mock_poe, mock_create_log, mock_isfile):
    """test check_start_parameters with all sys attribute"""

    mock_isfile.return_value = True
    test_fuse = Fuse()
    argv.clear()
    argv.extend(['dumy_path_to_file', 'test_file', '-log', '-output'])

    test_content = test_fuse.check_start_parameters()
    
    mock_poe.assert_called()
    mock_create_log.assert_called_with('Looging enabled by start parameter')
    mock_isfile.assert_called_with('test_file')
    assert test_content == 'test_file'

@patch('os.path.isfile')
@patch.object(Fuse, 'cerate_log')
@patch.object(Fuse, 'passwd_output_enable')
def test_check_start_parameters_wo_argv(mock_poe, mock_create_log, mock_isfile):
    """test check_start_parameters with out additional sys attribute"""
    mock_isfile.return_value = False

    test_fuse = Fuse()
    argv.clear()

    test_content = test_fuse.check_start_parameters()
    
    mock_poe.assert_not_called()
    mock_create_log.assert_not_called()
    mock_isfile.assert_not_called()
    assert test_content is None

@patch('fuse.datetime')
@patch('os.path.isfile')
@patch('logging.warning')
def test_password_output_enable(mock_warning, mock_isfile, mock_datetime):
    """test password_output_enable with enabled logs"""

    mock_isfile.return_value = True
    mock_datetime.now.return_value = '2022-04-08 00:00:00'
    test_fuse = Fuse()

    with patch('builtins.open', mock_open()) as test_file:
        test_fuse.passwd_output_enable()

    mock_warning.assert_called_with(
        '2022-04-08 00:00:00 - out.txt exists. The data will be appended to the file.'
    )
    mock_isfile.assert_called_with('out.txt')
    test_file.assert_called_with('out.txt', 'a', encoding='utf-8')
    test_file().write.assert_called_with('\n2022-04-08 00:00:00\n')
    assert test_fuse.passwd_output is True

@patch.object(Fuse, 'cerate_log')
@patch.object(Fuse, 'passwd_output_enable')
@patch('builtins.input')
def test_parameters_from_user_with_both(mock_input, mock_poe, mock_log):
    """test parameters_from_user when both option are selected"""
    test_fuse = Fuse()
    mock_input.return_value = 'Y'

    test_fuse.get_parameters_from_user()

    mock_poe.assert_called()
    mock_log.assert_called()

@patch.object(Fuse, 'cerate_log')
@patch.object(Fuse, 'passwd_output_enable')
def test_parameters_from_user_with_log(mock_poe, mock_log):
    """test parameters_from_user when -log option are selected"""
    test_fuse = Fuse()
    #answer_list = ['N', 'Y']

    #mock_input.return_value = answer_list.pop()
    with patch('builtins.input') as mock_input:
        mock_input.return_value = 'Y'
        test_fuse.get_parameters_from_user()

    mock_poe.assert_not_called()
    mock_log.assert_called()