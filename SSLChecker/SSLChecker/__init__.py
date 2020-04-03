import json
import logging
from time import process_time

import azure.functions as func

from ..sharedcode import shared_dns
from ..sharedcode import scanner
from ..sharedcode import results

external_dns, internal_dns = shared_dns.get_dns_options()

dnsview = {"external": external_dns,
           "internal": internal_dns}

# Valid scan types
valid_scan_types = ['policy', 'full']


def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    starttime = process_time()

    scan_type = req.route_params.get('scan')
    view = req.route_params.get('view')
    name = req.route_params.get('name')

    """ Check to ensure ALL parameters were passed in the URI.
    If you mark the route parameters in function.json as mandatory,
     the Azure Function worker supplies a 404 if you do not supply all
     three routes in the URI. I made routes optional, this way we
     can handle errors gracefully """
    if scan_type is None or view is None or name is None:
        error = {"Message": ("Please pass three parameters in the URI:"
                             " valid scan type: policy or full, "
                             "valid DNS view: internal or external, "
                             "and a valid DNS domain name")
                 }
        return json.dumps(error)

    # Check to ensure a valid scan type was passed
    scan_type = scan_type.lower()
    if scan_type not in valid_scan_types:
        error = {"Scan Type:": f'{scan_type}',
                 "Message": ("Please pass a valid scan"
                             " type: policy or full")
                 }
        return json.dumps(error)

    # Check to ensure a valid DNS view was passed
    view = view.lower()
    if view not in dnsview:
        error = {"View:": f'{view}',
                 "Message": ("Please pass a valid DNS view"
                             ": internal or external")
                 }
        return json.dumps(error)

    if dnsview.get(view) == '0.0.0.0':
        error = {"View:": f'{view}',
                 "Message": ("Please specify a valid DNS server"
                             " in config.ini")
                 }
        return json.dumps(error)

    # Parse the name parameter to ensure it is a valid DNS name
    # and does not contain http(s)
    try:
        name = shared_dns.parse_name(name)
    except Exception:
        error = results.set_error(f'{name}', "Not a valid formatted DNS name")
        return json.dumps(error)

    """ Try to resolve the DNS name to an IP to ensure it exists.
     We use the IP in the scan so that we can record which one we tested
     which can be useful. """
    try:
        ip = shared_dns.resolve_dns(dnsview.get(view), name)
    except Exception as err:
        error = results.set_error(f'{name}',
                                  str(err))
        return json.dumps(error)

    # Run the scan
    scanjob = scanner.scan(name, ip, view, scan_type)
    elapsedtime = process_time() - starttime
    logging.info(f'{name} processed for {elapsedtime}')
    return json.dumps(scanjob)
