import json
import logging
from typing import Tuple, Mapping
from time import process_time
from urllib.parse import urlparse

import azure.functions as func

from ..sharedcode import shared_dns
from ..sharedcode import scanner
from ..sharedcode import results
from ..sharedcode.errors import (InvalidRequest, DNSError, InvalidConfig,
                                 ConnectionError, InvalidFQDN)

external_dns, internal_dns = shared_dns.get_dns_options()

dnsview = {"external": external_dns,
           "internal": internal_dns}

# Valid scan types
VALID_SCAN_TYPES = ['policy', 'full']

ERROR_MSG_MISSING_PARAMETERS = \
    ("Please pass three parameters in the URI: "
     "valid scan type: policy or full, valid DNS view: internal or external, "
     "and a valid DNS domain name. For example: "
     "https://sslchecker.metlife.com/api/full/external/www.google.com")

ERROR_MSG_INVALID_SCANNER_TYPE = \
    "Please pass a valid scan type: 'policy' or 'full'"

ERROR_MSG_INVALID_VIEW = \
    "Please pass a valid DNS view: internal or external"

ERROR_MSG_MISSING_DNS_SERVER = \
    "Please specify a valid DNS server in config.ini"

ERROR_MSG_INVALID_DNS_NAME = \
    "Not a valid formatted DNS name"

ERROR_MSG_INVALID_PORT = \
    "Please pass a valid port in range 1-65535"

def verify_port(port:str) -> int:
    """
    raises InvalidRequest
    """
    if port.isnumeric() is False:
        raise InvalidRequest(f"Invalid Port '{port}'", ERROR_MSG_INVALID_PORT)
    _port = int(port)
    if _port > 65535 or _port == 0:
        raise InvalidRequest(f"Invalid Port '{port}'", ERROR_MSG_INVALID_PORT)
    return _port


def verify_scan_type(scan_type:str) -> str:
    """
    verify scan type is valid
    """
    scan_type = scan_type.lower()
    if scan_type not in VALID_SCAN_TYPES:
        raise InvalidRequest(f"Invalid scanner type '{scan_type}'",
                             ERROR_MSG_INVALID_SCANNER_TYPE)
    return scan_type


def pre_scan_check(req: func.HttpRequest) -> Tuple[str, str, str, int, str]:
    """
    return scan_type, view, name, and port, ip as a tuple if the request is
    valid.

    raises
    ------
    InvalidRequest
    InvalidConfig
    DNSError
    """
    scan_type = req.route_params.get('scan')
    view = req.route_params.get('view')
    name = req.route_params.get('name')
    port = req.route_params.get('port', '443')
    port = verify_port(port)

    """ Check to ensure ALL parameters were passed in the URI.
    If you mark the route parameters in function.json as mandatory,
     the Azure Function worker supplies a 404 if you do not supply all
     three routes in the URI. I made routes optional, this way we
     can handle errors gracefully """
    if scan_type is None or view is None or name is None:
        raise InvalidRequest("Missing Parameter(s)",
                             ERROR_MSG_MISSING_PARAMETERS)

    scan_type = verify_scan_type(scan_type)
    # Check to ensure a valid DNS view was passed
    view = view.lower()
    if view not in dnsview:
        raise InvalidRequest(f"Invalid View '{view}'", ERROR_MSG_INVALID_VIEW)

    # this maybe best handled as part of loading the app instead of checking it
    # here
    if dnsview.get(view) == '0.0.0.0':
        raise InvalidConfig('Missing DNS Server in config',
                            ERROR_MSG_MISSING_DNS_SERVER)

    # Parse the name parameter to ensure it is a valid DNS name
    # and does not contain http(s)
    name = shared_dns.parse_name(name)

    """ Try to resolve the DNS name to an IP to ensure it exists.
     We use the IP in the scan so that we can record which one we tested
     which can be useful. """
    ip = shared_dns.resolve_dns(dnsview.get(view), name)

    return scan_type, view, name, port, ip

def path_params_scanner(req: func.HttpRequest) -> str:
    """
    perform actual scan for path based parameters
    """
    try:
        scan_type, view, name, port, ip = pre_scan_check(req)
        # Run the scan
        return json.dumps(scanner.scan(name, ip, port, view, scan_type))
    except (InvalidRequest, InvalidConfig, DNSError, ConnectionError,
            InvalidFQDN) as err:
        return json.dumps(results.set_error(err.args[0], err.args[1]))
    except Exception as err:
        return json.dumps(results.set_error("Unexpected Error", str(err)))


VALID_QUERY_PARAMS = ('host', 'nameserver', 'port', 'scan_type')

ERROR_MSG_QUERY_EXAMPLE = (
    "Example: https://sslchecker.metlife.com/api/ssl?"
    "host=www.yahoo.com&port=8443")

ERROR_MSG_INVALID_QUERY_PARAMS = ( "Valid params are: "
                                  f"{', '.join(VALID_QUERY_PARAMS)}")
ERROR_MSG_INVALID_QUERY_URL = ( "Valid URL path must be 'ssl' or 'tls'. "
                               f"{ERROR_MSG_QUERY_EXAMPLE}")
ERROR_MSG_INVALID_QUERY_MISSING_PARAMS = ( "'host' parameters is required. "
                                          f"{ERROR_MSG_QUERY_EXAMPLE}")

def query_scanner_precheck(url:str,
                           params:Mapping[str, str]
                           ) -> Tuple[str, str, int, str, str, str]:
    """
    check to ensure the url path as well as the query parameters are valid

    returns
    -------
    scan_type, host, port, ip, nameserver, view

    raises
    ------
    InvalidRequest
    """

    if url.lower() not in VALID_QUERY_API_URL:
        raise InvalidRequest(f"Invalid URL Path '{url}'",
                             ERROR_MSG_INVALID_QUERY_URL)
    if 'host' not in params:
        raise InvalidRequest(f'Missing required parameter',
                             ERROR_MSG_INVALID_QUERY_MISSING_PARAMS)
    host = shared_dns.parse_name(params['host'])
    scan_type = 'full'
    port = '443'
    nameserver = None

    for param in params:
        if param not in VALID_QUERY_PARAMS:
            raise InvalidRequest(f"Invalid Parameter supplied '{param}'",
                                 ERROR_MSG_INVALID_QUERY_PARAMS)
        if param == 'scan_type':
            scan_type = verify_scan_type(params[param])
        elif param == 'nameserver':
            nameserver = params[param]
        elif param == 'port':
            port = verify_port(params[param])

    view = 'custom'
    if nameserver is None:
        if external_dns:
            view = 'external'
            nameserver = external_dns
        else:
            view = 'internal'
            nameserver = internal_dns

    ip = shared_dns.resolve_dns(nameserver, host)

    return scan_type, host, port, ip, nameserver, view


VALID_QUERY_API_URL = ('ssl', 'tls')

def query_params_scanner(url:str, params:Mapping[str, str]) -> str:
    """
    new function behavior to handle query based scanner, it would default
    to external DNS view before using the Internal
    """
    try:
        scan_type, host, port, ip, nameserver, view = \
            query_scanner_precheck(url, params)
        return json.dumps(scanner.scan(host, ip, port, view, scan_type))
    except (InvalidRequest, InvalidConfig, DNSError, ConnectionError,
            InvalidFQDN) as err:
        return json.dumps(results.set_error(err.args[0], err.args[1]))
    except Exception as err:
        return json.dumps(results.set_error("Unexpected Error", str(err)))


def main(req: func.HttpRequest) -> str:
    logging.info( 'Python HTTP trigger function processed a request '
                 f'for url: {req.url}.')
    starttime = process_time()
    url_parsed = urlparse(req.url)
    url_path = [v for v in url_parsed.path.split('/')[2:] if v]

    if not url_path or len(url_path) > 1 or url_path[0] in VALID_SCAN_TYPES:
        resp = path_params_scanner(req)
    else:
        resp = query_params_scanner(url_path[0], req.params)

    logging.info(f'Processed time for URL {req.url} took {process_time() - starttime}')

    return resp
