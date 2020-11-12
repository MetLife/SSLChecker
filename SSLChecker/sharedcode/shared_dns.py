""" Shared module for dns operations """

import pathlib
from configparser import ConfigParser, ParsingError
from typing import Tuple
from urllib.parse import urlparse

from dns import resolver
from validators import domain
from .errors import InvalidConfig, InvalidFQDN, UnknownError, DNSError

# Alias str type to better reflect the intented type and value
Fqdn = str
IpAddress = str


def get_dns_options() -> Tuple[str, str]:
    """
    Parse config.ini file and get internal and external dns servers
    """

    # https://github.com/Azure/azure-functions-python-worker/issues/340
    config_file = pathlib.Path(__file__).parent / "config.ini"
    parser = ConfigParser()

    try:
        parser.read_string(config_file.read_text())
        external_dns = parser.get("dns_view", "external")
        internal_dns = parser.get("dns_view", "internal")
    except ParsingError as err:
        raise InvalidConfig(
            f"Invalid Configuration File {config_file.resolve()}", err
        )

    return external_dns, internal_dns


def _init_resolver(dnsserver: IpAddress, timeout: int, lifetime: int) -> resolver.Resolver:
    """
    initialize a resolver
    """
    custom_resolver = resolver.Resolver(configure=False)
    custom_resolver.timeout = timeout
    custom_resolver.lifetime = lifetime
    custom_resolver.nameservers = [dnsserver]
    return custom_resolver


def resolve_dns(
        dnsserver: IpAddress, dnsname: Fqdn,
        timeout: int = 3, lifetime: int = 3
        ) -> IpAddress:
    """ Resolve dns name """
    _iplist = []  # results

    res = _init_resolver(dnsserver, timeout, lifetime)

    try:
        answers = res.resolve(dnsname, search=False)  # explicit query for A record
        for answer in answers.rrset:
            _iplist.append(answer.address)
        return _iplist[0]  # Return the first IP of the DNS Answer

    except resolver.NoAnswer:
        raise DNSError(
            "DNS No Answer", f"No Answer for {dnsname} using nameserver {dnsserver}"
        )
    except resolver.NXDOMAIN:
        raise DNSError(
            "DNS Non-Existing Domain",
            (f"Domain doesn't exist for {dnsname} using nameserver {dnsserver}"),
        )
    except resolver.Timeout:
        raise DNSError(
            "DNS operation timed out",
            (
                f"Operation not completed for {dnsname} within "
                f"{lifetime} using nameserver {dnsserver}"
            ),
        )

    # you don't know if the DNS server is truely
    # offline or network condition preventing the DNS request to get to the
    # server, it's best to just use another custom error for this condition
    except Exception:
        raise UnknownError(
            "DNS Unknown Error",
            (
                f"Error encountered while resolving {dnsname} "
                f"using nameserver {dnsserver}"
            ),
        )


def parse_name(name: str) -> Fqdn:
    """ Parse a DNS name to ensure it does not contain http(s) """
    parsed_name = urlparse(name)

    # The below parses out http(s) from a name
    dns_name_candidate = parsed_name.netloc
    if dns_name_candidate == "":
        dns_name_candidate = parsed_name.path

    # The below ensures a valid domain was supplied
    if not domain(dns_name_candidate):
        raise InvalidFQDN("Invalid FQDN", f"{name} is not a valid FQDN")

    return dns_name_candidate
