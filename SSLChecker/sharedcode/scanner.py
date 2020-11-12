from hashlib import md5
from typing import Dict, Any

from sslyze import (
    ServerNetworkLocationViaDirectConnection,
    ServerConnectivityTester,
    errors,
    ScanCommand,
    Scanner,
    ServerScanRequest,
)

from . import results
from .errors import ConnectionError

# Policy prohibits the use of SSL 2.0/3.0, TLS 1.0/1.1 and
# some TLS 1.2 cipher suites
CIPHER_SUITES = {
    "policy": [
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
    ],
    "full": [
        ScanCommand.SSL_2_0_CIPHER_SUITES,
        ScanCommand.SSL_3_0_CIPHER_SUITES,
        ScanCommand.TLS_1_0_CIPHER_SUITES,
        ScanCommand.TLS_1_1_CIPHER_SUITES,
        ScanCommand.TLS_1_2_CIPHER_SUITES,
        ScanCommand.TLS_1_3_CIPHER_SUITES,
    ],
}

# Currently, only The following TLS 1.2 ciphers are considered "strong"
OK_TLS12_CIPHERS = {
    "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    "TLS_DHE_RSA_WITH_AES_128_GCM_SHA256",
    "TLS_DHE_RSA_WITH_AES_256_GCM_SHA384",
    "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256"
}


ERROR_MSG_CONNECTION_TIMEOUT = "TCP connection to {}:{} timed-out".format
ERROR_MSG_UNKNOWN_CONNECTION = (
    "TCP connection to {}:{} encountered unknown error".format
)


def scan(target, ip, port, view, suite) -> Dict[str, Any]:
    """ Five inputs: web site name, ip, port
    split-dns view, and cipher suite """

    server_location = ServerNetworkLocationViaDirectConnection(target, port, ip)

    # This line checks to see if the host is online
    try:
        server_info = ServerConnectivityTester().perform(server_location)
    except errors.ConnectionToServerTimedOut:
        raise ConnectionError(
            "Connection Timeout", ERROR_MSG_CONNECTION_TIMEOUT(target, port)
        )
    except errors.ConnectionToServerFailed:
        raise ConnectionError(
            "Unknown Connection Error", ERROR_MSG_UNKNOWN_CONNECTION(target, port)
        )

    # Create a new results dictionary
    scan_output = results.new_result_set()

    # I hash the combination of hostname and ip for tracking
    key = md5((target + ip).encode("utf-8")).hexdigest()
    results.set_result(scan_output, "MD5", key)
    results.set_result(scan_output, "Target", f"{target}:{port}")
    results.set_result(scan_output, "IP", f"{ip}:{port}")
    results.set_result(scan_output, "Scan", suite)
    results.set_result(scan_output, "View", view)

    scanner = Scanner()
    # Ignore type error on get(key) as it defaults to None
    # https://docs.python.org/3/library/stdtypes.html#dict.get
    # We supply the values in the dict
    server_scan_req = ServerScanRequest(
        server_info=server_info, scan_commands=CIPHER_SUITES.get(suite)  # type: ignore
    )
    scanner.queue_scan(server_scan_req)

    for result in scanner.get_results():
        for cipher_suite in CIPHER_SUITES.get(suite):
            scan_result = result.scan_commands_results[cipher_suite]

            for accepted_cipher_suite in scan_result.accepted_cipher_suites:
                if suite == "policy" and scan_result.tls_version_used.name == "TLS_1_2":
                    if (
                        accepted_cipher_suite.cipher_suite.name
                        not in OK_TLS12_CIPHERS
                    ):
                        results.set_ciphers(
                            scan_output,
                            {
                                "Version": f"{scan_result.tls_version_used.name}",
                                "Cipher": f"{accepted_cipher_suite.cipher_suite.name}",
                            },
                        )
                else:
                    results.set_ciphers(
                        scan_output,
                        {
                            "Version": f"{scan_result.tls_version_used.name}",
                            "Cipher": f"{accepted_cipher_suite.cipher_suite.name}",
                        },
                    )

    if len(scan_output["Results"]) == 0:
        results.set_result(scan_output, "Results", "No Policy Violations")

    return scan_output
