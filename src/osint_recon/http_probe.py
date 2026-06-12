"""
HTTP and HTTPS availability probing.

Captures status code, Server header, and the final URL after any
redirects. Both schemes are probed independently so that a host with
TLS issues still produces useful HTTP-side data.
"""

from typing import Any

import requests

from .constants import HTTP_TIMEOUT_SECONDS


def check_http_status(domain: str) -> dict[str, dict[str, Any]]:
    """
    Probe both HTTP and HTTPS endpoints on the domain.

    Captures the final status code (after redirects), the Server header,
    and the final URL the request resolved to.

    Returns a dict keyed by scheme ("http", "https"). Failed schemes are
    omitted from the result rather than included with error values.
    """
    print("\n[*] Checking HTTP/HTTPS Status...")
    results: dict[str, dict[str, Any]] = {}

    for scheme in ["http", "https"]:
        url = f"{scheme}://{domain}"
        try:
            response = requests.get(url, timeout=HTTP_TIMEOUT_SECONDS, allow_redirects=True)
            status = response.status_code
            server = response.headers.get("Server", "Not disclosed")
            final_url = response.url
            print(f"    [+] {scheme.upper():<6} Status: {status} | Server: {server} | Final URL: {final_url}")
            results[scheme] = {
                "status_code": status,
                "server": server,
                "final_url": final_url,
            }
        except requests.exceptions.SSLError:
            print(f"    [!] {scheme.upper():<6} SSL certificate error")
        except requests.exceptions.ConnectionError:
            print(f"    [-] {scheme.upper():<6} Connection refused or host unreachable")
        except requests.exceptions.Timeout:
            print(f"    [-] {scheme.upper():<6} Request timed out after {HTTP_TIMEOUT_SECONDS} seconds")
        except Exception as e:
            print(f"    [-] {scheme.upper():<6} Unexpected error: {e}")

    return results
