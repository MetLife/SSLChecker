""" SSLChecker pytest tests """

import json

import azure.functions as func

import SSLChecker.SSLChecker.main as _main

main = _main.main


def test_policy_external_no_violations():
    """ Test policy scan on an external host with no violations """

    req = func.HttpRequest(
        method='GET',
        body=b'',
        url='/api/',
        route_params={'scan': 'policy',
                      'view': 'external',
                      'target': 'api.metlife.com'}
        )

    # Call the function
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure there are no violations
    assert results["Results"] == 'No Policy Violations'


def test_full_external():
    """ Test full scan on an external host """
    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'full',
                      'view': 'external',
                      'target': 'github.com'}
        )

    # Call the function
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure there are no violations
    assert results["Results"] != 'No Policy Violations'


def test_policy_external_violations():
    """ Test policy scan on an external host with violations """

    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'policy',
                      'view': 'external',
                      'target': 'espn.com'}
        )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure there are violations
    assert results["Results"] != 'No Policy Violations'


def test_external_dns_name_not_resolved():
    """ Test dns name not resolved """

    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'policy',
                      'view': 'external',
                      'target': 'joegatt.com'}
        )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure the DNS name could not resolve
    assert 'No Answer for joegatt.com using nameserver ' in results["Message"]


def test_external_dns_name_not_exist():
    """ Test NXDOMAIN """

    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'policy',
                      'view': 'external',
                      'target': 'jeogatt.com'}
        )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)
    # Check the output to ensure the DNS name could not resolve
    assert "Domain doesn't exist for jeogatt.com" in results["Message"]


def test_external_sslyze_timeout():
    """ Test sslyze timeout """

    name = 'bbbbbbbbbbbbbbb.com'
    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'policy',
                      'view': 'external',
                      'target': name}
        )

    # Call the function
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure the DNS name could not resolve
    assert results["Message"] == f'TCP connection to {name}:443 timed-out'


def test_external_missing_target():
    """ Test a request with a missing hostname """

    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'policy',
                      'view': 'external',
                      'target': None}
        )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results['Error Type'] == 'Missing Parameter(s)'
    assert results["Message"] == _main.ERROR_MSG_MISSING_PARAMETERS


def test_bad_dns_view_input():
    """ Test bad dns view input """

    view_name = 'badinput'
    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'policy',
                      'view': view_name,
                      'target': 'microsoft.com'}
        )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results['Error Type'] == f"Invalid View '{view_name}'"
    assert results["Message"] == _main.ERROR_MSG_INVALID_VIEW


def test_bad_scan_type_input():
    """ Test bad scan type input """

    scan_type = 'pppppp'
    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': scan_type,
                      'view': 'external',
                      'target': 'microsoft.com'}
        )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results["Error Type"] == f"Invalid scanner type '{scan_type}'"
    assert results["Message"] == _main.ERROR_MSG_INVALID_SCANNER_TYPE


def test_missing_dns_view():
    """ Test not dns view input """

    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'policy',
                      'view': None,
                      'target': None}
        )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results["Error Type"] == 'Missing Parameter(s)'
    assert results["Message"] == _main.ERROR_MSG_MISSING_PARAMETERS


def test_invalid_dns_name():
    """ Test invalid dns name input """

    dns_name = 'bbbbbbbbb'
    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'policy',
                      'view': 'external',
                      'target': dns_name}
        )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results["Error Type"] == 'Invalid FQDN'
    assert ' is not a valid FQDN' in results["Message"]


def test_missing_policy_view_dns_name():
    """ Test missing scan, view, and target """

    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': None, # type: ignore
                      'view': None,
                      'target': None}
        )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    print(results)
    assert results["Error Type"] == 'Missing Parameter(s)'
    assert results["Message"] == _main.ERROR_MSG_MISSING_PARAMETERS


def test_external_bad_port():
    """ Test bad port input """

    dns_name = 'yahoo.com'
    port = 'a'
    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'policy',
                      'view': 'external',
                      'target': dns_name,
                      'port': port}
        )

    # Call the function
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure the DNS name could not resolve
    assert results['Error Type'] == f"Invalid Port '{port}'"
    assert results["Message"] == _main.ERROR_MSG_INVALID_PORT


def test_external_port_timeout():
    """ Test timeout connecting to a port """

    dns_name = 'yahoo.com'
    port = '8443'
    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'policy',
                      'view': 'external',
                      'target': dns_name,
                      'port': '8443'}
        )

    # Call the function
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure the DNS name could not resolve
    assert results['Error Type'] == 'Connection Timeout'
    assert results["Message"] == f'TCP connection to {dns_name}:{port} timed-out'


def test_external_port_not_in_range():
    """ Test port not in valid range """

    port = '123456'
    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'policy',
                      'view': 'external',
                      'target': 'espn.com',
                      'port': port}
        )

    # Call the function
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure the DNS name could not resolve
    assert results['Error Type'] == f"Invalid Port '{port}'"
    assert results["Message"] == _main.ERROR_MSG_INVALID_PORT


def test_query_api():
    """ Test query api """

    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/tls',
        params={'target': 'www.google.com', 'nameserver': '8.8.8.8'}
        )
    resp = main(req)
    assert 'Results' in resp


def test_query_api_by_ip():
    """ Test query api by ip """

    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/tls',
        params={'target': '140.82.113.4', 'nameserver': '8.8.8.8'}
        )
    resp = main(req)
    assert 'Results' in resp


def test_query_api_error_handling():
    """ Test missing target """

    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/tls',
        params={'nameserver': '8.8.8.8'}
        )
    resp = main(req)
    results = json.loads(resp)
    assert results['Error Type'] == "Missing required parameter"


def test_policy_external_by_ip_no_violations():
    """ Test policy scan on an external ip with no violations """

    req = func.HttpRequest(
        method='GET',
        body=b"",
        url='/api/',
        route_params={'scan': 'policy',
                      'view': 'external',
                      'target': '216.163.251.205'}
        )
    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure there are violations
    assert results["Results"] == 'No Policy Violations'
