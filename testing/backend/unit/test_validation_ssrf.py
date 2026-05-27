"""
Tests for SSRF vulnerability fix in hostname validation.

These tests verify that hostnames resolving to blocked IP addresses
are properly rejected, preventing SSRF attacks against:
- Cloud metadata services (169.254.169.254)
- Link-local addresses
- Multicast addresses
- Loopback addresses (when disabled)
- Public IPs in safe mode
"""

import pytest
import asyncio
from unittest.mock import patch, AsyncMock
from backend.secuscan.validation import (
    validate_target_async,
    resolve_hostname_to_ips,
    _validate_ip_address,
    BLOCKED_NETWORKS,
    ALLOWED_PRIVATE
)


@pytest.mark.asyncio
async def test_resolve_hostname_to_ips():
    """Test DNS resolution returns IP addresses."""
    # Test with localhost (should resolve to 127.0.0.1 and/or ::1)
    ips = await resolve_hostname_to_ips("localhost")
    assert len(ips) > 0
    assert any(ip.startswith("127.") or ip == "::1" for ip in ips)


@pytest.mark.asyncio
async def test_validate_ip_address_blocked_networks():
    """Test that IPs in blocked networks are rejected."""
    # Link-local (169.254.0.0/16)
    is_valid, msg = _validate_ip_address("169.254.169.254", safe_mode=False)
    assert not is_valid
    assert "blocked network" in msg.lower()

    # Multicast (224.0.0.0/4)
    is_valid, msg = _validate_ip_address("224.0.0.1", safe_mode=False)
    assert not is_valid
    assert "blocked network" in msg.lower()

    # Broadcast (0.0.0.0/8)
    is_valid, msg = _validate_ip_address("0.0.0.0", safe_mode=False)
    assert not is_valid
    assert "blocked network" in msg.lower()


@pytest.mark.asyncio
async def test_validate_ip_address_safe_mode():
    """Test that public IPs are blocked in safe mode."""
    # Public IP should be blocked in safe mode
    is_valid, msg = _validate_ip_address("8.8.8.8", safe_mode=True)
    assert not is_valid
    assert "safe mode" in msg.lower()

    # Public IP should be allowed when safe mode is off
    is_valid, msg = _validate_ip_address("8.8.8.8", safe_mode=False)
    assert is_valid

    # Private IP should be allowed in safe mode
    is_valid, msg = _validate_ip_address("192.168.1.1", safe_mode=True)
    assert is_valid


@pytest.mark.asyncio
async def test_hostname_resolving_to_metadata_service():
    """Test SSRF Scenario 1: Hostname resolving to cloud metadata service."""
    # Mock DNS resolution to return metadata service IP
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock_resolve:
        mock_resolve.return_value = ["169.254.169.254"]

        is_valid, msg = await validate_target_async("metadata.attacker.com", safe_mode=False)
        assert not is_valid
        assert "blocked" in msg.lower()
        # Hostname should NOT be leaked in error message for security
        assert "metadata.attacker.com" not in msg


@pytest.mark.asyncio
async def test_hostname_resolving_to_private_network():
    """Test SSRF Scenario 3: Hostname resolving to private network."""
    # Mock DNS resolution to return private IP
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock_resolve:
        mock_resolve.return_value = ["10.0.0.1"]

        # Should be blocked in safe mode if it's a public hostname
        # But allowed if it resolves to private IP in safe mode
        is_valid, msg = await validate_target_async("internal.attacker.com", safe_mode=True)
        # Private IPs are allowed in safe mode
        assert is_valid


@pytest.mark.asyncio
async def test_hostname_resolving_to_loopback():
    """Test that hostname resolving to loopback is handled correctly."""
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock_resolve:
        mock_resolve.return_value = ["127.0.0.1"]

        # Should be blocked if allow_loopback_scans is False
        with patch('backend.secuscan.validation.settings.allow_loopback_scans', False):
            is_valid, msg = await validate_target_async("localhost.attacker.com", safe_mode=False)
            assert not is_valid
            assert "loopback" in msg.lower()


@pytest.mark.asyncio
async def test_hostname_resolving_to_multicast():
    """Test that hostname resolving to multicast address is blocked."""
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock_resolve:
        mock_resolve.return_value = ["224.0.0.1"]

        is_valid, msg = await validate_target_async("multicast.attacker.com", safe_mode=False)
        assert not is_valid
        assert "blocked" in msg.lower()


@pytest.mark.asyncio
async def test_hostname_resolving_to_multiple_ips_one_blocked():
    """Test that if any resolved IP is blocked, the hostname is rejected."""
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock_resolve:
        # Return both a valid private IP and a blocked link-local IP
        mock_resolve.return_value = ["192.168.1.1", "169.254.169.254"]

        is_valid, msg = await validate_target_async("mixed.attacker.com", safe_mode=False)
        assert not is_valid
        assert "blocked" in msg.lower()


@pytest.mark.asyncio
async def test_hostname_dns_resolution_failure():
    """Test that DNS resolution failures are handled gracefully."""
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock_resolve:
        import socket
        mock_resolve.side_effect = socket.gaierror("Name or service not known")

        is_valid, msg = await validate_target_async("nonexistent.invalid", safe_mode=False)
        assert not is_valid
        assert "could not be resolved" in msg.lower()
        # Hostname should NOT be leaked
        assert "nonexistent.invalid" not in msg


@pytest.mark.asyncio
async def test_valid_hostname_with_valid_ip():
    """Test that valid hostnames resolving to valid IPs are accepted."""
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock_resolve:
        mock_resolve.return_value = ["192.168.1.100"]

        is_valid, msg = await validate_target_async("valid.example.com", safe_mode=True)
        assert is_valid
        assert msg == ""


@pytest.mark.asyncio
async def test_url_with_hostname_resolving_to_blocked_ip():
    """Test that URLs with hostnames are also validated."""
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock_resolve:
        mock_resolve.return_value = ["169.254.169.254"]

        is_valid, msg = await validate_target_async("http://metadata.attacker.com/api", safe_mode=False)
        assert not is_valid
        assert "169.254.169.254" in msg


@pytest.mark.asyncio
async def test_direct_ip_still_works():
    """Test that direct IP validation still works (no DNS lookup needed)."""
    # Valid private IP
    is_valid, msg = await validate_target_async("192.168.1.1", safe_mode=True)
    assert is_valid

    # Blocked link-local IP
    is_valid, msg = await validate_target_async("169.254.169.254", safe_mode=False)
    assert not is_valid

    # Public IP blocked in safe mode
    is_valid, msg = await validate_target_async("8.8.8.8", safe_mode=True)
    assert not is_valid


@pytest.mark.asyncio
async def test_cidr_notation_still_works():
    """Test that CIDR notation validation still works."""
    # Valid private CIDR
    is_valid, msg = await validate_target_async("192.168.1.0/24", safe_mode=True)
    assert is_valid

    # Blocked network CIDR
    is_valid, msg = await validate_target_async("169.254.0.0/16", safe_mode=False)
    assert not is_valid


@pytest.mark.asyncio
async def test_hostname_with_port_in_url():
    """Test that hostnames with ports in URLs are validated correctly."""
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock_resolve:
        mock_resolve.return_value = ["169.254.169.254"]

        is_valid, msg = await validate_target_async("http://metadata.attacker.com:8080/api", safe_mode=False)
        assert not is_valid
        assert "169.254.169.254" in msg


@pytest.mark.asyncio
async def test_ipv6_hostname_resolution():
    """Test that IPv6 addresses from DNS resolution are validated."""
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock_resolve:
        # Return IPv6 loopback
        mock_resolve.return_value = ["::1"]

        with patch('backend.secuscan.validation.settings.allow_loopback_scans', False):
            is_valid, msg = await validate_target_async("ipv6.example.com", safe_mode=False)
            assert not is_valid
            assert "loopback" in msg.lower()


@pytest.mark.asyncio
async def test_empty_dns_response():
    """Test that empty DNS responses are handled."""
    with patch('backend.secuscan.validation.resolve_hostname_to_ips') as mock_resolve:
        mock_resolve.return_value = []

        is_valid, msg = await validate_target_async("empty.example.com", safe_mode=False)
        assert not is_valid
        assert "could not be resolved" in msg.lower()
