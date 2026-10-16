"""Check HTTPS certificate expiration and TLS validation."""
import asyncio
import ssl
from contextlib import suppress
from datetime import datetime, timedelta, timezone
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes

from bbot.core.config.models import BaseModuleConfig, Field
from bbot.modules.base import BaseModule


class certificate_health(BaseModule):
    watched_events = ["DNS_NAME", "OPEN_TCP_PORT"]
    produced_events = ["FINDING"]
    flags = ["active", "safe"]
    meta = {
        "description": "Check HTTPS certificate expiration and TLS validation",
        "created_date": "2026-10-16",
        "author": "@GunjanPantha",
    }
    deps_pip = ["cryptography>=42"]
    in_scope_only = True
    accept_seeds = True
    _module_threads = 4
    _disable_auto_module_deps = True

    class Config(BaseModuleConfig):
        warning_days: int = Field(30, ge=0, description="Warn this many days before expiry")
        ports: list[int] = Field([443], description="HTTPS ports to check on each DNS name")
        timeout: float = Field(8.0, gt=0, le=60, description="Seconds per TLS connection")
        ca_file: str = Field("", description="Optional PEM CA bundle to add to system trust")

    async def setup(self):
        self.warning_days = self.config.get("warning_days", 30)
        self.ports = tuple(dict.fromkeys(self.config.get("ports", [443])))
        self.timeout = self.config.get("timeout", 8.0)
        if not self.ports or any(not 1 <= p <= 65535 for p in self.ports):
            return False, "ports must contain TCP port numbers between 1 and 65535"

        # Verification is always enabled here, independently of BBOT's HTTP settings.
        try:
            self._verified_context = ssl.create_default_context()
            ca_file = self.config.get("ca_file", "")
            if ca_file:
                self._verified_context.load_verify_locations(str(Path(ca_file).expanduser()))
        except (OSError, ssl.SSLError) as exc:
            return False, f"Cannot load certificate trust settings: {exc}"

        # Used ONLY to inspect a certificate after verification has failed.
        # No HTTP requests, credentials, or application data are sent.
        self._inspection_context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        self._inspection_context.check_hostname = False
        self._inspection_context.verify_mode = ssl.CERT_NONE
        self._checked = set()
        self._attempted = self._findings = self._inconclusive = 0
        return True

    async def filter_event(self, event):
        # accept_seeds can bypass BBOT's distance check; enforce scope here too.
        if event.scope_distance != 0 or not event.host:
            return False, "Only in-scope hosts are checked"
        if self.helpers.is_ip(event.host):
            return False, "Use a DNS hostname to select the correct TLS certificate"
        if str(event.host).startswith("_wildcard."):
            return False, "Skip BBOT's synthetic wildcard hostname"
        if event.type == "OPEN_TCP_PORT" and event.port not in self.ports:
            return False, "Port is not in certificate_health.ports"
        return True

    async def handle_event(self, event):
        host = str(event.host).rstrip(".").lower()
        ports = [event.port] if event.type == "OPEN_TCP_PORT" else self.ports
        for port in ports:
            # A DNS event and a port event may describe the same endpoint.
            key = (host, port)
            if key in self._checked:
                continue
            self._checked.add(key)  # Mark before awaiting, so concurrent events dedupe.
            self._attempted += 1
            await self._check_endpoint(host, port, event)

    async def _read_certificate(self, host, port, context):
        _, writer = await asyncio.wait_for(
            asyncio.open_connection(
                host=host,
                port=port,
                ssl=context,
                server_hostname=host,
                ssl_handshake_timeout=self.timeout,
            ),
            timeout=self.timeout,
        )
        try:
            der = writer.get_extra_info("ssl_object").getpeercert(binary_form=True)
            peer_ip = writer.get_extra_info("peername")[0]
            return der, peer_ip
        finally:
            writer.close()
            with suppress(OSError, asyncio.TimeoutError):
                await asyncio.wait_for(writer.wait_closed(), timeout=1.0)

    async def _check_endpoint(self, host, port, event):
        verification_error = None
        der = None
        peer_ip = "unknown"
        try:
            der, peer_ip = await self._read_certificate(host, port, self._verified_context)
        except ssl.SSLCertVerificationError as exc:
            verification_error = (exc.verify_code, exc.verify_message)
            try:
                der, peer_ip = await self._read_certificate(host, port, self._inspection_context)
            except (OSError, asyncio.TimeoutError) as inspection_error:
                self.verbose(f"{host}:{port}: could not inspect leaf certificate: {inspection_error}")
                self._inconclusive += 1
        except (OSError, asyncio.TimeoutError) as exc:
            # No usable TLS connection is not evidence of a bad certificate.
            self._inconclusive += 1
            self.verbose(f"{host}:{port}: TLS check inconclusive: {exc}")
            return

        now = datetime.now(timezone.utc)
        date_problem = None
        if der:
            try:
                cert = x509.load_der_x509_certificate(der)
                expires = cert.not_valid_after_utc
                starts = cert.not_valid_before_utc
                fingerprint = cert.fingerprint(hashes.SHA256()).hex()
            except (ValueError, TypeError) as exc:
                self._inconclusive += 1
                self.verbose(f"{host}:{port}: cannot parse certificate: {exc}")
            else:
                # Expiration is checked independently, even when a chain error
                # prevents OpenSSL from reaching the certificate-date check.
                evidence = (
                    f"Leaf valid from {starts.isoformat()} through {expires.isoformat()}; "
                    f"observed {now.isoformat()}; peer {peer_ip}; SHA256 {fingerprint}."
                )
                if now > expires:
                    date_problem = "expired"
                    await self._finding(
                        event, host, port, "TLS certificate expired", "LOW", "tls-expired",
                        f"Certificate has expired. {evidence} Renew and deploy the certificate.",
                    )
                elif now < starts:
                    date_problem = "not-yet-valid"
                    await self._finding(
                        event, host, port, "TLS certificate not yet valid", "LOW", "tls-not-yet-valid",
                        f"Certificate is not valid yet. {evidence} Check certificate dates and system clocks.",
                    )
                elif expires - now <= timedelta(days=self.warning_days):
                    days = (expires - now).total_seconds() / 86400
                    await self._finding(
                        event, host, port, "TLS certificate expiring soon", "INFO", "tls-expiring",
                        f"Certificate expires in {days:.1f} days. {evidence} Schedule renewal.",
                    )

        if verification_error:
            code, message = verification_error
            # Avoid reporting the same date defect twice. A separate chain or
            # hostname error remains a separate finding, even on an expired leaf.
            duplicate_date_error = (code == 10 and date_problem == "expired") or (
                code == 9 and date_problem == "not-yet-valid"
            )
            if not duplicate_date_error:
                await self._finding(
                    event, host, port, "TLS certificate validation failed", "LOW", "tls-validation-failed",
                    f"Verified TLS handshake failed: OpenSSL code {code}: {message}. "
                    f"Observed {now.isoformat()} using this scanner's configured CA trust store. "
                    "Review hostname, server certificate chain, and client trust settings. "
                    "This error alone does not prove missing intermediates. "
                    "Any leaf-certificate details come from a separate inspection connection.",
                )
        elif der:
            self.verbose(f"{host}:{port}: TLS certificate validation passed")

    async def _finding(self, parent, host, port, name, severity, tag, description):
        url = f"https://{host}:{port}/"
        await self.emit_event(
            {
                "host": host,
                "url": url,
                "name": name,
                "description": f"{host}:{port}: {description}",
                "severity": severity,
                # Confirms the observation, not a particular server-side root cause.
                "confidence": "CONFIRMED",
            },
            "FINDING",
            parent=parent,
            tags=["certificate-health", tag],
        )
        self._findings += 1

    async def report(self):
        self.info(
            f"Certificate health: {self._attempted} endpoints checked; "
            f"{self._findings} findings; {self._inconclusive} incomplete checks (details with -v)."
        )
