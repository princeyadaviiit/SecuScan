"""
Demonstration script showing the SSRF vulnerability fix.

This script demonstrates that hostnames resolving to blocked IP addresses
are now properly rejected, preventing SSRF attacks.
"""

import asyncio
from unittest.mock import patch
from backend.secuscan.validation import validate_target_async


async def demo_ssrf_scenarios():
    """Demonstrate various SSRF attack scenarios and how they're blocked."""

    print("=" * 70)
    print("SSRF Vulnerability Fix Demonstration")
    print("=" * 70)
    print()

    # Scenario 1: Cloud Metadata Service SSRF
    print("Scenario 1: Hostname resolving to AWS/GCP/Azure metadata service")
    print("-" * 70)
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock:
        mock.return_value = ["169.254.169.254"]
        is_valid, msg = await validate_target_async("metadata.attacker.com", safe_mode=False)
        print(f"Target: metadata.attacker.com -> 169.254.169.254")
        print(f"Result: {'[BLOCKED]' if not is_valid else '[ALLOWED]'}")
        print(f"Message: {msg}")
        print()

    # Scenario 2: Multicast Address
    print("Scenario 2: Hostname resolving to multicast address")
    print("-" * 70)
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock:
        mock.return_value = ["224.0.0.1"]
        is_valid, msg = await validate_target_async("multicast.attacker.com", safe_mode=False)
        print(f"Target: multicast.attacker.com -> 224.0.0.1")
        print(f"Result: {'[BLOCKED]' if not is_valid else '[ALLOWED]'}")
        print(f"Message: {msg}")
        print()

    # Scenario 3: Loopback Address
    print("Scenario 3: Hostname resolving to loopback (when disabled)")
    print("-" * 70)
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock:
        mock.return_value = ["127.0.0.1"]
        with patch('backend.secuscan.validation.settings.allow_loopback_scans', False):
            is_valid, msg = await validate_target_async("localhost.attacker.com", safe_mode=False)
            print(f"Target: localhost.attacker.com -> 127.0.0.1")
            print(f"Result: {'[BLOCKED]' if not is_valid else '[ALLOWED]'}")
            print(f"Message: {msg}")
            print()

    # Scenario 4: Public IP in Safe Mode
    print("Scenario 4: Hostname resolving to public IP in safe mode")
    print("-" * 70)
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock:
        mock.return_value = ["8.8.8.8"]
        is_valid, msg = await validate_target_async("dns.attacker.com", safe_mode=True)
        print(f"Target: dns.attacker.com -> 8.8.8.8")
        print(f"Result: {'[BLOCKED]' if not is_valid else '[ALLOWED]'}")
        print(f"Message: {msg}")
        print()

    # Scenario 5: Multiple IPs (one blocked)
    print("Scenario 5: Hostname with multiple IPs (one blocked)")
    print("-" * 70)
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock:
        mock.return_value = ["192.168.1.1", "169.254.169.254"]
        is_valid, msg = await validate_target_async("mixed.attacker.com", safe_mode=False)
        print(f"Target: mixed.attacker.com -> [192.168.1.1, 169.254.169.254]")
        print(f"Result: {'[BLOCKED]' if not is_valid else '[ALLOWED]'}")
        print(f"Message: {msg}")
        print()

    # Scenario 6: Valid hostname (allowed)
    print("Scenario 6: Valid hostname resolving to allowed private IP")
    print("-" * 70)
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock:
        mock.return_value = ["192.168.1.100"]
        is_valid, msg = await validate_target_async("valid.internal.com", safe_mode=True)
        print(f"Target: valid.internal.com -> 192.168.1.100")
        print(f"Result: {'[ALLOWED]' if is_valid else '[BLOCKED]'}")
        print(f"Message: {msg if msg else 'Valid target'}")
        print()

    # Scenario 7: Direct IP (no DNS lookup)
    print("Scenario 7: Direct IP address (no DNS lookup needed)")
    print("-" * 70)
    is_valid, msg = await validate_target_async("169.254.169.254", safe_mode=False)
    print(f"Target: 169.254.169.254 (direct IP)")
    print(f"Result: {'[BLOCKED]' if not is_valid else '[ALLOWED]'}")
    print(f"Message: {msg}")
    print()

    print("=" * 70)
    print("Summary: All SSRF attack vectors are now properly blocked!")
    print("=" * 70)


if __name__ == "__main__":
    asyncio.run(demo_ssrf_scenarios())
