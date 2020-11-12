# Changelog for SSLChecker

# v1.0.0
- Initial Release

# v1.1.0
- Added the ability to pass a port to SSLScanner

# v1.2.0
- Added some type annotations and more consistent error for the main function

# v1.3.0
- Added the ability to scan by IP

# v2.0.0
- Upgraded [SSLyze](https://github.com/nabla-c0d3/sslyze) to 3.x
- Added several TLS 1.2 ciphers to the "policy" scan type as "weak"
- Added scan type and port to result set

# v2.1.0
- Upgraded dnspython to 2.0.x and fixed deprecated call to dns.resolver.query()
- Upgraded validators to 0.17
- Various pylint and type checking fixes

# v2.2.0
- Upgraded SSLyze to 3.1
- Removed pytest from requirements
- Various pylint and type checking fixes
- Removed TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256 and TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256 from "strong" TLS 1.2 ciphers