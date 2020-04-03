import pathlib
from configparser import ConfigParser, ParsingError
from urllib.parse import urlparse

from dns import resolver
from validators import domain


def get_dns_options():
    '''
    Parse config.ini file and get internal and external dns servers
    '''

    # https://github.com/Azure/azure-functions-python-worker/issues/340
    config_file_path = pathlib.Path(__file__).parent / 'config.ini'
    parser = ConfigParser()

    try:
        parser.read_file(open(config_file_path))
    except ParsingError as err:
        print(err)

    try:
        external_dns = parser.get('dns_view', 'external')
        internal_dns = parser.get('dns_view', 'internal')
    except ParsingError as err:
        print(err)

    return external_dns, internal_dns


def resolve_dns(dnsserver, dnsname):
    ''' Resolve dns name '''
    _iplist = []  # results

    # dnspython config
    resolver.Cache.flush  # flush dnspython cache
    res = resolver.Resolver(configure=False)  # Do not read resolv.conf
    res.timeout = 3
    res.lifetime = 3  # How many seconds a query should run before timing out
    res.nameservers = [dnsserver]  # DNS server may not be online
    #  Need better error handling in case internal DNS server is not online
    #  Right now it just times out the query, which is handled below

    try:
        answers = res.query(dnsname)
        for answer in answers:
            _iplist.append(answer.address)
        return _iplist[0]  # Return the first IP of the DNS Answer
    except resolver.NoAnswer:
        raise ValueError("Domain exits but no A record")
    except resolver.NXDOMAIN:
        raise ValueError("The DNS name does not exist")
    except resolver.Timeout:
        raise ValueError("The DNS operation timed out")
    except resolver.NoNameservers as err:
        raise ValueError(err.msg)  # Should trigger if a DNS server is offline
    except Exception:
        # If you are here, you are jacked
        raise ValueError("Catch all error in /sharedcode/shared_dns.py")


def parse_name(name):
    ''' Parse a DNS name to ensure it does not contain http(s) '''
    _parsed_name = urlparse(name)

    # The below parses out http(s) from a name
    if not _parsed_name.netloc:
        _parsed_name = _parsed_name.path
    else:
        _parsed_name = _parsed_name.netloc

    # The below ensures a valid domain was supplied
    if domain(_parsed_name):
        return _parsed_name
    else:
        raise Exception  # Valid formatted DNS name not provided
