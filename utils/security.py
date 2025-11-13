"""
Security Utilities - Helper Functions
======================================

Provides security helper functions and examples of safe practices
"""

import hashlib
import secrets
import html
import re
from typing import Optional


def hash_password(password: str, salt: Optional[str] = None) -> tuple:
    """
    Securely hash a password using SHA-256
    Returns (hashed_password, salt)
    """
    if salt is None:
        salt = secrets.token_hex(16)
    
    salted_password = f"{password}{salt}"
    hashed = hashlib.sha256(salted_password.encode()).hexdigest()
    return hashed, salt


def verify_password(password: str, hashed_password: str, salt: str) -> bool:
    """Verify a password against a hash"""
    computed_hash, _ = hash_password(password, salt)
    return computed_hash == hashed_password


def escape_html(text: str) -> str:
    """
    Safely escape HTML to prevent XSS
    This is an example of proper output encoding
    """
    return html.escape(text)


def sanitize_sql_input(input_value: str) -> str:
    """
    Example SQL sanitization (NOT recommended - use parameterized queries instead)
    This is here for educational purposes only
    """
    # Remove SQL injection characters
    dangerous_chars = ["'", '"', ';', '--', '/*', '*/']
    sanitized = input_value
    for char in dangerous_chars:
        sanitized = sanitized.replace(char, '')
    return sanitized


def validate_email(email: str) -> bool:
    """Validate email format using regex"""
    pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return bool(re.match(pattern, email))


def validate_username(username: str) -> bool:
    """
    Validate username format
    Only allows alphanumeric and underscore, 3-20 characters
    """
    pattern = r'^[a-zA-Z0-9_]{3,20}$'
    return bool(re.fullmatch(pattern, username))


def generate_csrf_token() -> str:
    """Generate a secure CSRF token"""
    return secrets.token_urlsafe(32)


def generate_session_id() -> str:
    """Generate a secure session ID"""
    return secrets.token_hex(32)


class SecurityHeaders:
    """Security headers for HTTP responses"""
    
    @staticmethod
    def get_default_headers() -> dict:
        """Get recommended security headers"""
        return {
            'X-Content-Type-Options': 'nosniff',
            'X-Frame-Options': 'DENY',
            'X-XSS-Protection': '1; mode=block',
            'Strict-Transport-Security': 'max-age=31536000; includeSubDomains',
            'Content-Security-Policy': "default-src 'self'"
        }


def is_safe_redirect(url: str) -> bool:
    """
    Validate redirect URLs to prevent open redirect vulnerabilities
    Only allows relative URLs or same-origin absolute URLs
    """
    if url.startswith('/'):
        # Relative URL is safe
        return True
    
    if url.startswith(('http://', 'https://')):
        # Check if it's our domain (simplified check)
        # In production, validate against whitelist
        return False
    
    return False


def sanitize_filename(filename: str) -> str:
    """
    Sanitize filenames to prevent path traversal
    Remove directory separators and special characters
    """
    # Remove path components
    filename = filename.replace('..', '')
    filename = filename.replace('/', '')
    filename = filename.replace('\\', '')
    
    # Keep only safe characters
    filename = re.sub(r'[^a-zA-Z0-9._-]', '', filename)
    
    return filename
