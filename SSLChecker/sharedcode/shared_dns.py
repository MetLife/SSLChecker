import pathlib
from configparser import ConfigParser, ParsingError
from urllib.parse import urlparse
from dns import resolver
from validators import domain
from .errors import InvalidConfig, InvalidFQDN, UnknownError
from typing import Tuple
import os

def get_dns_options() -> Tuple[str, str]:
    '''
    Parse config.ini file and get internal and external dns servers
    '''

    # https://github.com/Azure/azure-functions-python-worker/issues/340
    config_file = pathlib.Path(__file__).parent / 'config.ini'
    parser = ConfigParser()

    try:
        parser.read_string(config_file.read_text())
        external_dns = parser.get('dns_view', 'external')
        internal_dns = parser.get('dns_view', 'internal')
    except ParsingError as err:
        raise InvalidConfig(f'{config_file.resolve()}', err)

    return external_dns, internal_dns

# alias str type to better reflect the intented type and value
fqdn = str
ip = str

def _init_resolver(dnsserver:ip, timeout = 3, lifetime = 3) -> resolver.Resolver:
    """
    initialize a resolver
    """
    custom_resolver = resolver.Resolver(configure=False)
    custom_resolver.timeout = timeout
    custom_resolver.lifetime = lifetime
    custom_resolver.nameservers = [dnsserver]
    return custom_resolver

def resolve_dns(dnsserver:ip, dnsname:fqdn) -> ip:
    ''' Resolve dns name '''
    _iplist = []  # results

    # Note to original author
    # dnspython config
    # actually, this is NOT needed, if you read the Resolver code, unless
    # supplied a Cache object, it doesn't cache. in addition, the code
    # below did not really flush the Cache, The Cache is a Class, flush
    # is just a method, to do so, you really need to create a Cache object
    # and then call the flush method as below
    # i.e cache = resolver.Cache(); cache.flush()

    #resolver.Cache.flush  # flush dnspython cache

    res = _init_resolver(dnsserver)

    try:
        answers = res.query(dnsname, 'A')   # explicit query for A record
        for answer in answers:
            _iplist.append(answer.address)
        return _iplist[0]  # Return the first IP of the DNS Answer
    except resolver.NoAnswer:
        raise ValueError("Domain exits but no A record")
    except resolver.NXDOMAIN:
        raise ValueError("The DNS name does not exist")
    except resolver.Timeout:
        raise ValueError("The DNS operation timed out")
    # you don't know if the DNS server is truely
    # offline or network condition preventing the DNS request to get to the
    # server, it's best to just use another custom error for this condition
    except Exception as err:
        raise UnknownError(
            (f'unknown error encounter while resolving {dnsname}'
             f'using dns server {dnsserver}'), err)

def parse_name(name:str) -> fqdn:
    ''' Parse a DNS name to ensure it does not contain http(s) '''
    parsed_name = urlparse(name)

    # The below parses out http(s) from a name
    dns_name_candidate = parsed_name.netloc
    if dns_name_candidate == '':
        dns_name_candidate = parsed_name.path

    # The below ensures a valid domain was supplied
    if domain(dns_name_candidate):
        return dns_name_candidate
    else:
        raise InvalidFQDN(f'{name} is not a valid FQDN')  # Valid formatted DNS name not provided
