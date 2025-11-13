"""
Admin Service - Admin-Protected Functionality
==============================================

Contains functionality that is only accessible to administrators:
1. Audit log queries (admin-only, SQL injection but protected)
2. Template preview with defense-in-depth (admin + CSRF + rate limit + sanitization)

These demonstrate false_positive_protected vulnerabilities
"""

from typing import Dict, List, Any
from services.database_service import DatabaseService
from services.template_service import TemplateService
import time
from collections import defaultdict


class AdminService:
    """Admin service with admin-protected vulnerabilities"""
    
    def __init__(self):
        self.db_service = DatabaseService()
        self.template_service = TemplateService()
        
        # Rate limiting state
        self.rate_limit_state = defaultdict(list)
        self.rate_limit_window = 60  # 60 seconds
        self.rate_limit_max_requests = 10
    
    # ==================== VULN 6: FALSE POSITIVE - Admin Protected ====================
    
    def get_audit_logs(self, date_filter: str) -> List[Dict[str, Any]]:
        """
        VULN 6: FALSE POSITIVE - false_positive_protected (Subcategory 3A - Strong Auth/Authz)
        
        This function contains a SQL injection vulnerability but is protected by:
        1. @admin_required decorator in app.py (requires authentication + admin role)
        2. Admin-only functionality - only admins need audit logs
        3. Impact equivalent to legitimate admin actions
        
        Even though there's a technical vulnerability, it's only exploitable by
        authenticated administrators who already have high privileges
        
        Attack path: request.args → date_filter → get_audit_logs → 
                     db_service.get_audit_logs_by_date (SQL injection sink)
        
        Protection: @admin_required prevents non-admin exploitation
        """
        # This calls the vulnerable database function
        # But it's only accessible to admins due to @admin_required decorator
        logs = self.db_service.get_audit_logs_by_date(date_filter)
        
        # Additional admin-only business logic
        enriched_logs = self._enrich_audit_logs(logs)
        return enriched_logs
    
    def _enrich_audit_logs(self, logs: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Add additional context to audit logs (admin-only operation)"""
        for log in logs:
            log['admin_view'] = True
            log['sensitive_data_visible'] = True
        return logs
    
    # ==================== VULN 7: FALSE POSITIVE - Defense in Depth ====================
    
    def preview_template(self, template_content: str) -> str:
        """
        VULN 7: FALSE POSITIVE - false_positive_protected (Subcategory 3B - Defense in Depth)
        
        This function has template injection but is protected by MULTIPLE layers:
        1. @admin_required decorator - admin authentication + authorization
        2. CSRF protection - Flask POST request with session token
        3. Rate limiting - _check_rate_limit() prevents abuse
        4. Content sanitization - template_service.render_admin_preview() sanitizes input
        
        This demonstrates how multiple weak/medium controls combine for strong protection
        
        Attack path: request.json → template_content → preview_template → 
                     _check_rate_limit → template_service.render_admin_preview (template injection sink)
        
        Protection: Defense-in-depth (multiple independent layers)
        """
        # Layer 1: Rate limiting
        if not self._check_rate_limit('admin_template_preview'):
            return "<div class='error'>Rate limit exceeded. Try again later.</div>"
        
        # Layer 2: Content length restriction
        if len(template_content) > 5000:
            return "<div class='error'>Template content too large (max 5000 chars)</div>"
        
        # Layer 3: Call template service which applies sanitization
        # The template_service.render_admin_preview() applies _sanitize_template_content()
        preview = self.template_service.render_admin_preview(template_content)
        
        # Layer 4: Additional output filtering
        preview = self._filter_admin_output(preview)
        
        return preview
    
    def _check_rate_limit(self, operation: str) -> bool:
        """
        Rate limiting implementation - part of defense-in-depth
        Prevents rapid exploitation attempts
        """
        current_time = time.time()
        
        # Clean old entries outside the window
        self.rate_limit_state[operation] = [
            timestamp for timestamp in self.rate_limit_state[operation]
            if current_time - timestamp < self.rate_limit_window
        ]
        
        # Check if limit exceeded
        if len(self.rate_limit_state[operation]) >= self.rate_limit_max_requests:
            return False
        
        # Add current request
        self.rate_limit_state[operation].append(current_time)
        return True
    
    def _filter_admin_output(self, output: str) -> str:
        """
        Additional output filtering for admin previews
        Part of the defense-in-depth strategy
        """
        # Remove potentially dangerous HTML attributes
        dangerous_attrs = ['onerror', 'onload', 'onclick', 'onmouseover']
        filtered = output
        for attr in dangerous_attrs:
            filtered = filtered.replace(attr, 'data-blocked')
        return filtered
    
    # ==================== ADMIN UTILITY FUNCTIONS ====================
    
    def validate_admin_action(self, action: str) -> bool:
        """
        Validates that an admin action is allowed
        Additional security check for admin operations
        """
        allowed_actions = ['view_logs', 'preview_template', 'manage_users', 'system_config']
        return action in allowed_actions
