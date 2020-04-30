"""
Raised when config.ini is not valid
"""
class InvalidConfig(Exception):
    pass

class InvalidFQDN(Exception):
    pass

class UnknownError(Exception):
    pass
