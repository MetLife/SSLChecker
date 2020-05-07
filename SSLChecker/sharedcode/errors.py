"""
Custom Exception for the app
"""


class InvalidConfig(Exception):
    pass


class InvalidFQDN(Exception):
    pass


class UnknownError(Exception):
    pass


class InvalidRequest(Exception):
    pass


class DNSError(Exception):
    pass


class ConnectionError(Exception):
    pass
