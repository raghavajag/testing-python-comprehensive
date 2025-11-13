"""
Template Service - Template Injection Test Cases
=================================================

Contains various template injection sinks with different protection levels:
1. Vulnerable render_template_string (TRUE POSITIVE - good_to_fix)
2. Auth-protected template rendering (FALSE POSITIVE - protected)
3. Admin-protected with defense-in-depth (FALSE POSITIVE - protected)
"""

from flask import render_template_string
import html
import re
from typing import Dict, Any


class TemplateService:
    """Template service with various template injection patterns"""
    
    def __init__(self):
        self.user_preferences = {}
    
    # ==================== VULN 4: TRUE POSITIVE - Weak Validation ====================
    
    def render_user_template(self, template_code: str) -> str:
        """
        VULN 4: TRUE POSITIVE - good_to_fix
        Template injection with weak validation
        
        The validation from ValidationService.check_template_safety() only checks
        for obvious patterns like {{ and {% but can be bypassed with techniques like:
        - Unicode encoding
        - Nested expressions
        - Alternative template syntax
        
        This demonstrates a vulnerability with partial protection
        """
        # Even though there's validation, it's weak and can be bypassed
        template_str = f"<div>User Content: {template_code}</div>"
        return render_template_string(template_str)  # VULN 4: TEMPLATE INJECTION SINK
    
    # ==================== VULN 5: FALSE POSITIVE - Auth Protected ====================
    
    def render_preference_template(self, user_id: int, preference_key: str) -> str:
        """
        VULN 5: FALSE POSITIVE - false_positive_protected (Strong Auth)
        Template injection but protected by authentication
        
        This is called from get_preferences() which has @login_required decorator
        Additionally, it only renders user's own preferences, limiting the impact
        
        Protection layers:
        1. @login_required - must be authenticated
        2. User-scoped data - can only affect own account
        3. Limited template context - no access to dangerous objects
        """
        # Get user's preference (user-scoped data)
        user_prefs = self.user_preferences.get(user_id, {})
        pref_value = user_prefs.get(preference_key, 'default')
        
        # This LOOKS vulnerable but is protected by auth + limited scope
        template_str = f"<span>Your preference '{preference_key}': {pref_value}</span>"
        return render_template_string(template_str)  # VULN 5: TEMPLATE INJECTION SINK (but auth-protected)
    
    # ==================== VULN 7: FALSE POSITIVE - Defense in Depth ====================
    
    def render_admin_preview(self, template_content: str) -> str:
        """
        VULN 7: FALSE POSITIVE - false_positive_protected (Defense in Depth)
        Template injection with multiple protection layers
        
        This is called from AdminService.preview_template() which has:
        1. @admin_required - admin authentication + authorization
        2. CSRF protection (implied by Flask/POST)
        3. Rate limiting (application-level)
        4. Content sanitization before rendering
        
        This demonstrates how multiple weak controls combine for strong protection
        """
        # Multiple protection layers make this safe despite template injection
        sanitized_content = self._sanitize_template_content(template_content)
        template_str = f"<div class='preview'>{sanitized_content}</div>"
        return render_template_string(template_str)  # VULN 7: TEMPLATE INJECTION SINK (but defense-in-depth)
    
    def _sanitize_template_content(self, content: str) -> str:
        """
        Apply content sanitization to remove dangerous template syntax
        This is part of the defense-in-depth strategy
        """
        # Remove template markers
        content = content.replace('{{', '').replace('}}', '')
        content = content.replace('{%', '').replace('%}', '')
        # HTML escape to prevent XSS
        content = html.escape(content)
        return content
    
    # ==================== SAFE TEMPLATES ====================
    
    def render_safe_notification(self, notification_text: str) -> str:
        """
        Example of safe template rendering using auto-escaping
        This should NOT be flagged as vulnerable
        """
        # Safe: using variable substitution with auto-escaping
        template_str = "<div class='notification'>{{ notification }}</div>"
        return render_template_string(template_str, notification=notification_text)
    
    def render_html_escaped(self, user_input: str) -> str:
        """
        Example of safe template with HTML escaping
        This should NOT be flagged as vulnerable
        """
        # Safe: HTML escaped before template
        escaped_input = html.escape(user_input)
        template_str = f"<p>Safe content: {escaped_input}</p>"
        return render_template_string(template_str)
