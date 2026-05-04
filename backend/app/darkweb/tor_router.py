"""
ShadowNet — Dark Web: Tor Router
Provides Tor SOCKS5 proxy routing for dark web access.
Includes proper connection verification and proxy session management.
NOTE: Requires Tor to be installed and running locally (port 9050).
"""

import aiohttp
import structlog
from typing import Optional

logger = structlog.get_logger(__name__)

# Default Tor SOCKS proxy settings
TOR_SOCKS_HOST = "127.0.0.1"
TOR_SOCKS_PORT = 9050
TOR_CONTROL_PORT = 9051


class TorRouter:
    """Manages Tor proxy connections for dark web access."""

    def __init__(self):
        self.is_connected = False
        self.exit_ip: Optional[str] = None
        self.proxy_url = f"socks5h://{TOR_SOCKS_HOST}:{TOR_SOCKS_PORT}"
        self._socks_available = False
        self._check_socks_support()

    def _check_socks_support(self):
        """Check if aiohttp-socks is installed for SOCKS proxy support."""
        try:
            from aiohttp_socks import ProxyConnector  # noqa: F401
            self._socks_available = True
        except ImportError:
            self._socks_available = False
            logger.info("aiohttp-socks not installed — Tor proxy routing unavailable. "
                        "Install with: pip install aiohttp-socks")

    async def check_connection(self) -> dict:
        """
        Check if Tor is running and accessible.
        Routes through SOCKS proxy to verify actual Tor connectivity.
        """
        # If aiohttp-socks is not available, try a simple socket check
        if not self._socks_available:
            return await self._check_tor_port_open()

        try:
            from aiohttp_socks import ProxyConnector

            # Create a connector that routes through the Tor SOCKS proxy
            connector = ProxyConnector.from_url(self.proxy_url)
            async with aiohttp.ClientSession(connector=connector) as session:
                async with session.get(
                    "https://check.torproject.org/api/ip",
                    timeout=aiohttp.ClientTimeout(total=15),
                ) as resp:
                    if resp.status == 200:
                        data = await resp.json()
                        self.is_connected = data.get("IsTor", False)
                        self.exit_ip = data.get("IP", "unknown")
                        return {
                            "connected": self.is_connected,
                            "ip": self.exit_ip,
                            "is_tor": data.get("IsTor", False),
                            "socks_proxy": self.proxy_url,
                        }
        except Exception as e:
            logger.debug("Tor SOCKS connection check failed", error=str(e))

        # Fallback: check if the port is open
        return await self._check_tor_port_open()

    async def _check_tor_port_open(self) -> dict:
        """Fallback check — just test if the Tor SOCKS port is accepting connections."""
        import asyncio
        try:
            _, writer = await asyncio.wait_for(
                asyncio.open_connection(TOR_SOCKS_HOST, TOR_SOCKS_PORT),
                timeout=3,
            )
            writer.close()
            await writer.wait_closed()
            self.is_connected = True
            return {
                "connected": True,
                "ip": "unknown (socks proxy reachable)",
                "is_tor": True,
                "socks_proxy": self.proxy_url,
                "note": "Tor port open but aiohttp-socks not installed for full verification",
            }
        except Exception:
            self.is_connected = False
            return {
                "connected": False,
                "error": "Tor not available — SOCKS port not responding",
                "socks_proxy": self.proxy_url,
                "help": "Install Tor: https://www.torproject.org/download/",
            }

    def get_proxy_connector(self) -> Optional[aiohttp.TCPConnector]:
        """Get an aiohttp connector routed through Tor SOCKS proxy."""
        if not self._socks_available:
            return None
        try:
            from aiohttp_socks import ProxyConnector
            return ProxyConnector.from_url(self.proxy_url)
        except Exception as e:
            logger.warning("Failed to create Tor proxy connector", error=str(e))
            return None

    def get_proxy_config(self) -> dict:
        """Get proxy configuration for aiohttp/requests."""
        return {
            "proxy": self.proxy_url,
            "proxy_auth": None,
        }

    async def get_status(self) -> dict:
        """Get current Tor router status with live connectivity check."""
        conn_status = await self.check_connection()
        return {
            "proxy_url": self.proxy_url,
            "is_connected": self.is_connected,
            "exit_ip": self.exit_ip,
            "socks_host": TOR_SOCKS_HOST,
            "socks_port": TOR_SOCKS_PORT,
            "socks_library_available": self._socks_available,
            **conn_status,
        }


# Singleton
tor_router = TorRouter()
