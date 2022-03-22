"""gnerate password object"""

from hashlib import sha1
from dataclasses import dataclass, field

@dataclass(repr=False, frozen=True)
class Passwd():
    """Converting input string to bytes and sha1"""
    raw_pass : str
    byte_pass : bytes = field(init=False, repr=False, default = None)
    hash_pass : str = field(init=False, repr=False, default= None)

    def __post_init__(self):
        object.__setattr__(self, 'byte_pass', self.raw_pass.encode('utf-8'))
        object.__setattr__(self, 'hash_pass', sha1(self.byte_pass).hexdigest())
