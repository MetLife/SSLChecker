import json
import logging
from typing import Tuple
from time import process_time

import azure.functions as func

from ..sharedcode import shared_dns
from ..sharedcode import scanner
from ..sharedcode import results
from ..sharedcode.errors import InvalidRequest, DNSError, InvalidConfig

external_dns, internal_dns = shared_dns.get_dns_options()

dnsview = {"external": external_dns,
           "internal": internal_dns}

# Valid scan types
valid_scan_types = ['policy', 'full']

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

def pre_scan_check(req: func.HttpRequest) -> Tuple[str, str, str, int, str]:
    """
    return scan_type, view, name, and port, ip as a tuple if the request is
    valid.

    raises
    ------
    InvalidRequest
    InvalidConfig
    """
    scan_type = req.route_params.get('scan')
    view = req.route_params.get('view')
    name = req.route_params.get('name')
    port = req.route_params.get('port', '443')
    if port.isnumeric() is False:
        raise InvalidRequest(f"Invalid Port '{port}'", ERROR_MSG_INVALID_PORT)
    if int(port) > 65535 or int(port) == 0:
        raise InvalidRequest(f"Invalid Port '{port}'", ERROR_MSG_INVALID_PORT)

    # Port is optional and will default to 443 if none is provided

    """ Check to ensure ALL parameters were passed in the URI.
    If you mark the route parameters in function.json as mandatory,
     the Azure Function worker supplies a 404 if you do not supply all
     three routes in the URI. I made routes optional, this way we
     can handle errors gracefully """
    if scan_type is None or view is None or name is None:
        raise InvalidRequest("Missing Parameter(s)",
                             ERROR_MSG_MISSING_PARAMETERS)

    # Check to ensure a valid scan type was passed
    scan_type = scan_type.lower()
    if scan_type not in valid_scan_types:
        raise InvalidRequest(f"Invalid scanner type '{scan_type}'",
                             ERROR_MSG_INVALID_SCANNER_TYPE)

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
    try:
        name = shared_dns.parse_name(name)
    except Exception:
        raise InvalidRequest(f"Invalid DNS Name '{name}'",
                             ERROR_MSG_INVALID_DNS_NAME)

    """ Try to resolve the DNS name to an IP to ensure it exists.
     We use the IP in the scan so that we can record which one we tested
     which can be useful. """
    try:
        ip = shared_dns.resolve_dns(dnsview.get(view), name)
    except Exception as err:
        raise DNSError(f"dns resolution error for '{name}'", str(err))

    return scan_type, view, name, port, ip

def main(req: func.HttpRequest) -> str:
    logging.info('Python HTTP trigger function processed a request.')
    starttime = process_time()

    try:
        scan_type, view, name, port, ip = pre_scan_check(req)

        # Run the scan
        scanjob = scanner.scan(name, ip, port, view, scan_type)
        elapsedtime = process_time() - starttime
        logging.info(f'{name} processed for {elapsedtime}')
        return json.dumps(scanjob)
    except (InvalidRequest, InvalidConfig, DNSError) as err:
        return json.dumps(results.set_error(err.args[0], err.args[1]))
    except Exception as err:
        return json.dumps(results.set_error("Unexpected Error", str(err)))
