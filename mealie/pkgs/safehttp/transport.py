import ipaddress
import logging
import socket
from typing import Iterable

import httpx


class ForcedTimeoutException(Exception):
    """
    Raised when a request takes longer than the timeout value.
    """

    ...


class InvalidDomainError(Exception):
    """
    Raised when a request is made to a local IP address.
    """

    ...


class AsyncSafeTransport(httpx.AsyncBaseTransport):
    """
    A wrapper around the httpx transport class that enforces a timeout value
    and that the request is not made to a local IP address.
    """

    timeout: int = 15

    def __init__(self, log: logging.Logger | None = None, **kwargs):
        self.timeout = kwargs.pop("timeout", self.timeout)
        self._wrapper = httpx.AsyncHTTPTransport(**kwargs)
        self._log = log

    async def handle_async_request(self, request) -> httpx.Response:
        # override timeout value for _all_ requests
        request.extensions["timeout"] = httpx.Timeout(self.timeout, pool=self.timeout).as_dict()

        # validate the request is not attempting to connect to a local IP
        # This is a security measure to prevent SSRF attacks

        def is_disallowed_ip(candidate: ipaddress._BaseAddress) -> bool:
            """Return True if the IP should be blocked for SSRF protection."""
            return (
                candidate.is_private
                or candidate.is_loopback
                or candidate.is_link_local
                or candidate.is_multicast
                or candidate.is_reserved
                or candidate.is_unspecified
                or candidate in ipaddress.ip_network("100.64.0.0/10")
            )

        def resolve_all(hostname: str) -> Iterable[ipaddress._BaseAddress]:
            """Resolve all A/AAAA records for a hostname; if it's already an IP, yield it."""
            try:
                # If hostname is a literal IP
                yield ipaddress.ip_address(hostname)
                return
            except ValueError:
                pass

            try:
                for family in (socket.AF_INET, socket.AF_INET6):
                    try:
                        infos = socket.getaddrinfo(hostname, None, family, socket.SOCK_STREAM)
                    except socket.gaierror:
                        continue
                    for info in infos:
                        addr = info[4][0]
                        try:
                            yield ipaddress.ip_address(addr)
                        except ValueError:
                            continue
            except Exception:
                # Fall back to single resolution
                try:
                    ip_str = socket.gethostbyname(hostname)
                    yield ipaddress.ip_address(ip_str)
                except Exception:
                    return

        netloc = request.url.netloc.decode()
        host = netloc.split(":", 1)[0]

        # Validate all resolved addresses
        for resolved_ip in resolve_all(host):
            if is_disallowed_ip(resolved_ip):
                if self._log:
                    self._log.warning(
                        f"invalid request on disallowed IP for {request.url} -> {resolved_ip}"
                    )
                raise InvalidDomainError(
                    f"invalid request on disallowed IP for {request.url} -> {resolved_ip}"
                )

        return await self._wrapper.handle_async_request(request)

    async def aclose(self):
        await self._wrapper.aclose()
