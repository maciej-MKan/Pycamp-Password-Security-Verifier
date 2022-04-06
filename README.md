# Pycamp-Password-Security-Verifier
Project from PyCamp module 2
Terminal script that checks passwords for security

## General info
The program will validate passwords in terms of:
* Lenght - minimum 8 chars
* The occurrence of lowercase characters - minimum 1
* The occurrence of upperercase characters - minimum 1
* The occurrence of special characters - minimum 1
* Has a password leak been revealed by haveibeenpwned.com

Passwords can be provided in a file (see pass.example) or entered directly

## Technologies
The program was created in Python 3.8 using the random, dataclass and requests libraries.

## Using

### As a script with attributes
To run the project, enter:
```
$ python fuse.py [file] [-log] [-output]
```
```
optional attributes:
[file] - file with a passwords (see pass.example)
[-log] - if present, the script will create a fuse.log with information about the validation process of your passwords
[-output] - if present, the script will create an out.txt file with secure passwords from among those given
```
### Directly
To run the project, enter:
```
$ python fuse.py
```
the program will ask for the above attributes
