"""tests for fuse.py"""

from sys import argv
from unittest.mock import patch, mock_open, Mock
from fuse import Fuse, InputFormer, PasswordChecker
from validator import Validator
from leak_check import LeakCheck
#pylint: disable=too-many-arguments

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

@patch('os.path.isfile')
@patch.object(Fuse, 'create_log')
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
@patch.object(Fuse, 'create_log')
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

@patch.object(Fuse, 'create_log')
@patch.object(Fuse, 'passwd_output_enable')
@patch('builtins.input')
def test_parameters_from_user_with_both(mock_input, mock_poe, mock_log):
    """test parameters_from_user when both option are selected"""
    test_fuse = Fuse()
    mock_input.return_value = 'Y'

    test_fuse.get_parameters_from_user()

    mock_poe.assert_called()
    mock_log.assert_called()

@patch.object(Fuse, 'create_log')
@patch.object(Fuse, 'passwd_output_enable')
def test_parameters_from_user_with_log(mock_poe, mock_log):
    """test parameters_from_user when -log option are selected"""

    test_fuse = Fuse()

    input_mock = Mock()
    input_mock.side_effect = ['Y','N']

    with patch('builtins.input', input_mock):
        test_fuse.get_parameters_from_user()

    mock_poe.assert_not_called()
    mock_log.assert_called()

@patch.object(Fuse, 'make_output_file')
@patch('fuse.logging')
@patch.object(Validator, '__bool__')
@patch.object(LeakCheck, '__bool__')
@patch('builtins.open', new_callable=mock_open, read_data=TEST_FILE_DATA)
@patch('os.path.isfile')
@patch('fuse.datetime')
def test_fuse_general(
    mock_datetime, mock_isfile, mock_file, mock_leak, mock_validator, mock_logging, mock_output
    ):
    """general test for fuse module called with argv"""

    mock_datetime.now.return_value = '2022-04-08 00:00:00'
    mock_isfile.return_value = True
    mock_leak.return_value = True
    mock_validator.return_value = True

    test_fuse = Fuse()
    test_fuse.log = True
    test_fuse.passwd_output = True

    rezult = test_fuse.check_password_safety('test_file')

    assert list(rezult) == [('line1', 'is safe'), ('line2', 'is safe'), ('line3', 'is safe')]
    assert all(True for out in ['line1', 'line2', 'line3'] if out in mock_output.mock_calls)
    assert all(
        True for out in ['line1 - is safe', 'line2 - is safe', 'line3 - is safe']\
            if out in mock_logging.mock_calls)
    mock_isfile.assert_called_with('test_file')
    mock_file.assert_called()
