"""
Validation Service - Input Validation and Sanitization
=======================================================

Provides various validation and sanitization methods to test false positive detection:
1. Strict numeric validation (prevents SQL injection)
2. Weak template safety check (partial protection)
3. Allowlist validation
"""

import re
from typing import Any


class ValidationService:
    """Validation service with various validation patterns"""
    
    ALLOWED_ACCOUNT_TYPES = ['savings', 'checking', 'business', 'investment']
    ALLOWED_ROLES = ['user', 'admin', 'manager', 'auditor']
    
    # ==================== STRICT VALIDATION (Effective Protection) ====================
    
    def validate_user_id(self, user_id: str) -> str:
        """
        CRITICAL for VULN 2: This provides effective protection against SQL injection
        
        Uses re.fullmatch() which ensures the ENTIRE string matches the pattern
        Pattern ^[0-9]+$ ensures only digits, no SQL metacharacters possible
        
        This is an example of Subcategory 2B (Validation-Based) false positive
        """
        # Strict validation - entire string must be numeric
        if not re.fullmatch(r'^[0-9]+$', user_id):
            raise ValueError(f"Invalid user ID format: {user_id}")
        return user_id
    
    def validate_numeric(self, value: str) -> str:
        """Strict numeric validation using fullmatch"""
        if not re.fullmatch(r'[0-9]+', str(value)):
            raise ValueError("Value must be numeric")
        return value
    
    def validate_account_type(self, account_type: str) -> str:
        """
        Allowlist validation - only pre-defined values allowed
        This is an example of effective validation for false positives
        """
        if account_type not in self.ALLOWED_ACCOUNT_TYPES:
            raise ValueError(f"Invalid account type: {account_type}")
        return account_type
    
    def validate_role(self, role: str) -> str:
        """
        Allowlist validation for user roles
        Demonstrates strict validation that prevents injection
        """
        if role not in self.ALLOWED_ROLES:
            raise ValueError(f"Invalid role: {role}")
        return role
    
    def validate_alphanumeric(self, value: str) -> bool:
        """
        CRITICAL for VULN 8 PATH 2: Validates that input is strictly alphanumeric
        
        Uses re.fullmatch() to ensure the ENTIRE string is alphanumeric + underscores
        This prevents SQL injection by disallowing quotes, semicolons, dashes, etc.
        
        This is used in the mixed scenario (VULN 8) to protect the live path
        """
        # Strict validation - only alphanumeric and underscores allowed
        if not re.fullmatch(r'^[a-zA-Z0-9_]+$', value):
            return False
        return True
    
    # ==================== WEAK VALIDATION (Partial Protection) ====================
    
    def check_template_safety(self, template_code: str) -> bool:
        """
        CRITICAL for VULN 4: This is WEAK validation
        
        Only checks for obvious template markers like {{ and {%
        Can be bypassed with:
        - Unicode encoding: \u007b\u007b instead of {{
        - Nested expressions: {​{7*7}}
        - Alternative syntax
        
        This demonstrates partial protection that should result in good_to_fix
        """
        # Weak validation - only checks obvious patterns
        dangerous_patterns = [
            r'\{\{',  # Jinja2 variable markers
            r'\{%',   # Jinja2 statement markers
            r'__',    # Python magic methods
            r'import',  # Import statements
            r'eval',  # Eval function
            r'exec',  # Exec function
        ]
        
        for pattern in dangerous_patterns:
            if re.search(pattern, template_code, re.IGNORECASE):
                return False
        
        # Passes weak validation but still vulnerable
        return True
    
    # ==================== SANITIZATION EXAMPLES ====================
    
    def sanitize_sql_input(self, input_value: str) -> str:
        """
        Example of SQL input sanitization
        In practice, parameterized queries are better
        """
        # Remove common SQL injection characters
        dangerous_chars = ["'", '"', ';', '--', '/*', '*/']
        sanitized = input_value
        for char in dangerous_chars:
            sanitized = sanitized.replace(char, '')
        return sanitized
    
    def sanitize_html(self, input_value: str) -> str:
        """
        Example of HTML sanitization
        In practice, use libraries like bleach or html.escape
        """
        # Basic HTML character escaping
        sanitized = input_value.replace('<', '&lt;')
        sanitized = sanitized.replace('>', '&gt;')
        sanitized = sanitized.replace('"', '&quot;')
        sanitized = sanitized.replace("'", '&#x27;')
        return sanitized

