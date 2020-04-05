import azure.functions as func
from SSLChecker.SSLChecker import main
import json


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
    assert results["Message"] == 'Connection to TCP 443 timed-out'


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
    assert results["Message"] == ("Please pass three parameters in the URI:"
                                  " valid scan type: policy or full, "
                                  "valid DNS view: internal or external, "
                                  "and a valid DNS domain name")


def test_bad_dns_view_input():
    # Construct a mock HTTP request
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': 'badinput',
                          'name': 'microsoft.com'}
            )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results["Message"] == ("Please pass a valid DNS view"
                                  ": internal or external")


def test_bad_policy_input():
    # Construct a mock HTTP request
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'pppppp',
                          'view': 'external',
                          'name': 'microsoft.com'}
            )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results["Message"] == ("Please pass a valid scan"
                                  " type: policy or full")


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
    assert results["Message"] == ("Please pass three parameters in the URI:"
                                  " valid scan type: policy or full, "
                                  "valid DNS view: internal or external, "
                                  "and a valid DNS domain name")


def test_bad_dns_name():
    # Construct a mock HTTP request
    req = func.HttpRequest(
            method='GET',
            body=None,
            url='/api/',
            route_params={'scan': 'policy',
                          'view': 'external',
                          'name': 'bbbbbbbbbb'}
            )

    # Call the function.
    resp = main(req)

    # Convert resp string to dict
    results = json.loads(resp)

    # Ensure error handling is working properly
    assert results["Message"] == "Not a valid formatted DNS name"


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
    assert results["Message"] == ("Please pass three parameters in the URI:"
                                  " valid scan type: policy or full, "
                                  "valid DNS view: internal or external, "
                                  "and a valid DNS domain name")
