"""TLS configuration utilities for mTLS communication."""

import os
import ssl
from pathlib import Path
from typing import Optional

import httpx


def get_certs_dir() -> Path:
    """Get the certificates directory path."""
    certs_dir = os.environ.get("CERTS_DIR", "/app/certs")
    return Path(certs_dir)


def get_ca_cert_path() -> Path:
    """Get the CA certificate path."""
    return get_certs_dir() / "ca.crt"


def get_service_cert_path(service: str) -> Path:
    """Get the service certificate path."""
    return get_certs_dir() / f"{service}.crt"


def get_service_key_path(service: str) -> Path:
    """Get the service private key path."""
    return get_certs_dir() / f"{service}.key"


def create_ssl_context(
    service_name: str,
    verify_client: bool = True,
) -> ssl.SSLContext:
    """
    Create an SSL context for a service.
    
    Args:
        service_name: Name of the service (for cert/key lookup)
        verify_client: Whether to verify client certificates (mTLS)
    
    Returns:
        Configured SSL context
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    cert_path = get_service_cert_path(service_name)
    key_path = get_service_key_path(service_name)
    ca_path = get_ca_cert_path()
    
    if cert_path.exists() and key_path.exists():
        context.load_cert_chain(str(cert_path), str(key_path))
    
    if verify_client and ca_path.exists():
        context.verify_mode = ssl.CERT_REQUIRED
        context.load_verify_locations(str(ca_path))
    else:
        context.verify_mode = ssl.CERT_NONE
    
    return context


def create_client_ssl_context(service_name: str) -> ssl.SSLContext:
    """
    Create an SSL context for a client making mTLS requests.
    
    Args:
        service_name: Name of the service (for client cert/key lookup)
    
    Returns:
        Configured SSL context for client use
    """
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    context.minimum_version = ssl.TLSVersion.TLSv1_2
    
    cert_path = get_service_cert_path(service_name)
    key_path = get_service_key_path(service_name)
    ca_path = get_ca_cert_path()
    
    if cert_path.exists() and key_path.exists():
        context.load_cert_chain(str(cert_path), str(key_path))
    
    if ca_path.exists():
        context.load_verify_locations(str(ca_path))
        context.check_hostname = False
        context.verify_mode = ssl.CERT_REQUIRED
    else:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    
    return context


def get_httpx_client(
    service_name: str,
    timeout: float = 5.0,
    use_mtls: bool = True,
) -> httpx.AsyncClient:
    """
    Get an httpx async client configured for mTLS.
    
    Args:
        service_name: Name of the calling service
        timeout: Request timeout in seconds
        use_mtls: Whether to use mTLS (True) or just verify server cert (False)
    
    Returns:
        Configured httpx AsyncClient
    """
    ca_path = get_ca_cert_path()
    cert_path = get_service_cert_path(service_name)
    key_path = get_service_key_path(service_name)
    
    if use_mtls and cert_path.exists() and key_path.exists() and ca_path.exists():
        return httpx.AsyncClient(
            timeout=timeout,
            verify=str(ca_path),
            cert=(str(cert_path), str(key_path)),
        )
    elif ca_path.exists():
        return httpx.AsyncClient(
            timeout=timeout,
            verify=str(ca_path),
        )
    else:
        return httpx.AsyncClient(
            timeout=timeout,
            verify=False,
        )


def is_tls_enabled() -> bool:
    """Check if TLS is enabled based on environment."""
    return os.environ.get("TLS_ENABLED", "false").lower() == "true"


def get_service_url(service: str, port: int, path: str = "") -> str:
    """Get the URL for a service, using HTTPS if TLS is enabled."""
    scheme = "https" if is_tls_enabled() else "http"
    return f"{scheme}://{service}:{port}{path}"
