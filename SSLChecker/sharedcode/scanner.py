from hashlib import md5

from sslyze.server_connectivity_tester import ServerConnectivityTester, \
    ServerConnectivityError, ConnectionToServerTimedOut
from sslyze.ssl_settings import TlsWrappedProtocolEnum
from sslyze.plugins.openssl_cipher_suites_plugin import Sslv20ScanCommand, \
    Sslv30ScanCommand, Tlsv10ScanCommand, Tlsv11ScanCommand, \
    Tlsv12ScanCommand, Tlsv13ScanCommand
from sslyze.synchronous_scanner import SynchronousScanner

from ..sharedcode import results

# Policy prohibits the use of SSL 2.0/3.0 and TLS 1.0
ciphersuites = {
                "policy": [Sslv20ScanCommand(), Sslv30ScanCommand(),
                           Tlsv10ScanCommand(), Tlsv11ScanCommand()],
                "full": [Sslv20ScanCommand(), Sslv30ScanCommand(),
                         Tlsv10ScanCommand(), Tlsv11ScanCommand(),
                         Tlsv12ScanCommand(), Tlsv13ScanCommand()]
                }

# sslyze config
SynchronousScanner.DEFAULT_NETWORK_RETRIES = 1
SynchronousScanner.DEFAULT_NETWORK_TIMEOUT = 3


def scan(name, ip, port, view, suite):
    """ Five inputs: web site name, ip, port
    split-dns view, and cipher suite """

    try:
        server_tester = ServerConnectivityTester(
            hostname=name,
            ip_address=ip,
            port=port,
            tls_wrapped_protocol=TlsWrappedProtocolEnum.HTTPS
            )
        # This line checks to see if the host is online
        server_info = server_tester.perform()
        ip = server_info.ip_address
    # Could not establish an SSL connection to the server
    except ConnectionToServerTimedOut:
        error = results.set_error(f'{name}',
                                  f"Connection to TCP {port} timed-out")
        return error
    except ServerConnectivityError:
        error = results.set_error(f'{name}',
                                  "Unknown Error")
        return error

    # Create a new results dictionary
    scan_output = results.new()

    # I hash the combination of hostname and ip for tracking
    key = md5((f'{name}' + ip).encode("utf-8")).hexdigest()
    results.set_result(scan_output, "MD5", key)
    results.set_result(scan_output, "Hostname", f'{name}')
    results.set_result(scan_output, "IP", ip)
    results.set_result(scan_output, "View", view)

    for suite in ciphersuites.get(suite):
        synchronous_scanner = SynchronousScanner()
        scan_result = synchronous_scanner.run_scan_command(server_info, suite)

        for cipher in scan_result.accepted_cipher_list:
            results.set_ciphers(scan_output,
                                {
                                 "Version": cipher.ssl_version.name,
                                 "Cipher": cipher.name
                                }
                                )

    if len(scan_output["Results"]) == 0:
        results.set_result(scan_output, "Results", "No Policy Violations")

    return scan_output
