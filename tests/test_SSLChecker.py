import azure.functions as func
import SSLChecker.SSLChecker.main as _main
import json

main = _main.main

def test_policy_external_no_violations():
    # Construct a mock HTTP request
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': 'external',
                          'name': 'microsoft.com'}
            )

    # Call the function
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure there are no violations
    assert results["Results"] == 'No Policy Violations'


def test_full_external():
    # Construct a mock HTTP request
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'full',
                          'view': 'external',
                          'name': 'github.com'}
            )

    # Call the function
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure there are no violations
    assert results["Results"] != 'No Policy Violations'


def test_policy_external_violations():
    # Construct a mock HTTP request
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': 'external',
                          'name': 'espn.com'}
            )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure there are violations
    assert results["Results"] != 'No Policy Violations'


def test_external_dns_name_not_resolved():
    # Construct a mock HTTP request
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': 'external',
                          'name': 'joegatt.com'}
            )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure the DNS name could not resolve
    assert results["Message"] == 'Domain exits but no A record'


def test_external_dns_name_not_exist():
    # Construct a mock HTTP request
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': 'external',
                          'name': 'jeogatt.com'}
            )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure the DNS name could not resolve
    assert results["Message"] == 'The DNS name does not exist'


def test_external_sslyze_timeout():
    # Construct a mock HTTP request
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': 'external',
                          'name': 'bbbbbbbbbbbbbbb.com'}
            )

    # Call the function
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure the DNS name could not resolve
    assert results['Error Type'] == 'Connection Timeout'
    assert results["Message"] == 'TCP connection to bbbbbbbbbbbbbbb.com:443 timed-out'


def test_external_missing_dns_name():
    # Construct a mock HTTP request
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': 'external',
                          'name': None}
            )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results['Error Type'] == 'Missing Parameter(s)'
    assert results["Message"] == _main.ERROR_MSG_MISSING_PARAMETERS


def test_bad_dns_view_input():
    # Construct a mock HTTP request
    view_name = 'badinput'
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': view_name,
                          'name': 'microsoft.com'}
            )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results['Error Type'] == f"Invalid View '{view_name}'"
    assert results["Message"] == _main.ERROR_MSG_INVALID_VIEW


def test_bad_policy_input():
    # Construct a mock HTTP request
    policy_type = 'pppppp'
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': policy_type,
                          'view': 'external',
                          'name': 'microsoft.com'}
            )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results["Error Type"] == f"Invalid scanner type '{policy_type}'"
    assert results["Message"] == _main.ERROR_MSG_INVALID_SCANNER_TYPE


def test_missing_dns_view():
    # Construct a mock HTTP request
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': None,
                          'name': None}
            )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results["Error Type"] == 'Missing Parameter(s)'
    assert results["Message"] == _main.ERROR_MSG_MISSING_PARAMETERS


def test_bad_dns_name():
    # Construct a mock HTTP request
    dns_name = 'bbbbbbbbb'
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': 'external',
                          'name': dns_name}
            )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results["Error Type"] == f"Invalid DNS Name '{dns_name}'"
    assert results["Message"] == _main.ERROR_MSG_INVALID_DNS_NAME


def test_missing_policy_view_dns_name():
    # Construct a mock HTTP request
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': None,
                          'view': None,
                          'name': None}
            )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results["Error Type"] == 'Missing Parameter(s)'
    assert results["Message"] == _main.ERROR_MSG_MISSING_PARAMETERS


def test_external_bad_port():
    # Construct a mock HTTP request
    dns_name = 'yahoo.com'
    port = 'a'
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': 'external',
                          'name': dns_name,
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
    # Construct a mock HTTP request
    dns_name = 'yahoo.com'
    port = '8443'
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': 'external',
                          'name': 'yahoo.com',
                          'port': '8443'}
            )

    # Call the function
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure the DNS name could not resolve
    assert results['Error Type'] == 'Unknow Connection Error'
    assert results["Message"] == f'TCP connection to {dns_name}:{port} encountered unknown error'


def test_external_port_not_in_range():
    # Construct a mock HTTP request
    port = '123456'
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': 'external',
                          'name': 'espn.com',
                          'port': port}
            )

    # Call the function
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Check the output to ensure the DNS name could not resolve
    assert results['Error Type'] == f"Invalid Port '{port}'"
    assert results["Message"] == _main.ERROR_MSG_INVALID_PORT
