"""
Python Banking Application - Security Testing Codebase
=======================================================

This Flask application is designed to test the AI-SAST analyzer's ability to:
1. Distinguish between true positives and false positives
2. Identify dead code paths vs. live vulnerable paths
3. Recognize effective sanitization and validation
4. Assess authentication/authorization protections
5. Handle complex attack paths with multiple hops
6. Handle MIXED SCENARIOS (multiple paths, different classifications)

VULNERABILITY DISTRIBUTION:
- Total Sinks: 8
- True Positives: 2 (25%) - must_fix or good_to_fix
- False Positives: 6 (75%)
  - FP Sanitized: 2 (Subcategory 2B: Validation, Subcategory 2C: Architectural)
  - FP Protected: 3 (Subcategory 3A: Auth/Authz, Subcategory 3B: Defense-in-Depth)
  - FP Mixed Scenario: 1 (Multiple paths: 2 dead, 1 live+sanitized)

TESTING COVERAGE:
✅ All 3 FP categories (sanitized, protected, dead_code/mixed)
✅ Subcategories: 2B (Validation), 2C (Architectural), 3A (Auth), 3B (Defense-in-Depth)
✅ Weak vs strong validation (good_to_fix vs false_positive)
✅ Multi-hop attack paths (2-4 hops)
✅ Mixed path scenarios (some dead, some live but protected)
✅ Dead code with multiple unreachable branches
"""

from flask import Flask, request, jsonify, session
from functools import wraps
import os

# Import services
from services.database_service import DatabaseService
from services.template_service import TemplateService
from services.validation_service import ValidationService
from services.admin_service import AdminService
from services.legacy_service import LegacyService

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Initialize services
db_service = DatabaseService()
template_service = TemplateService()
validation_service = ValidationService()
admin_service = AdminService()
legacy_service = LegacyService()


# ==================== AUTHENTICATION DECORATORS ====================

def login_required(f):
    """Basic authentication check"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        return f(*args, **kwargs)
    return decorated_function


def admin_required(f):
    """Admin authentication check with role verification"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'user_id' not in session:
            return jsonify({'error': 'Authentication required'}), 401
        if session.get('role') != 'admin':
            return jsonify({'error': 'Admin access required'}), 403
        return f(*args, **kwargs)
    return decorated_function


# ==================== PUBLIC ENDPOINTS (ENTRY POINTS) ====================

@app.route('/api/search', methods=['GET'])
def search_transactions():
    """
    VULN 1: TRUE POSITIVE - must_fix
    Direct SQL injection with no sanitization or validation
    Attack path: request.args → search_term → db_service.search_transactions_vulnerable
    """
    search_term = request.args.get('query', '')
    results = db_service.search_transactions_vulnerable(search_term)
    return jsonify(results)


@app.route('/api/user/profile', methods=['GET'])
def get_user_profile():
    """
    VULN 2: FALSE POSITIVE - false_positive_sanitized (Subcategory 2B - Validation-Based)
    SQL injection protected by strict validation before database query
    Attack path: request.args → user_id → validation_service.validate_user_id → 
                 db_service.get_user_by_id_with_validation
    """
    user_id = request.args.get('user_id', '')
    # Strict validation with allowlist pattern
    validated_id = validation_service.validate_user_id(user_id)
    user = db_service.get_user_by_id_with_validation(validated_id)
    return jsonify(user)


@app.route('/api/report/generate', methods=['POST'])
def generate_report():
    """
    VULN 3: FALSE POSITIVE - false_positive_sanitized (Subcategory 2C - Architectural)
    SQL injection protected by ORM query builder (architectural pattern)
    Attack path: request.json → report_type → db_service.generate_report_parameterized
    Protection: QueryBuilder class provides architectural SQL injection protection
    """
    report_type = request.json.get('report_type', '')
    user_filter = request.json.get('user_filter', '')
    report = db_service.generate_report_parameterized(report_type, user_filter)
    return jsonify(report)


@app.route('/api/render/custom', methods=['POST'])
def render_custom_template():
    """
    VULN 4: TRUE POSITIVE - good_to_fix
    Template injection with partial protection (validation exists but weak)
    Attack path: request.json → template_code → validation_service.check_template_safety (weak) →
                 template_service.render_user_template
    """
    template_code = request.json.get('template', '')
    # Weak validation - only checks for obvious patterns
    if validation_service.check_template_safety(template_code):
        result = template_service.render_user_template(template_code)
        return jsonify({'output': result})
    return jsonify({'error': 'Template rejected'}), 400


# ==================== AUTHENTICATED ENDPOINTS ====================

@app.route('/api/user/preferences', methods=['GET'])
@login_required
def get_preferences():
    """
    VULN 5: FALSE POSITIVE - false_positive_protected (Subcategory 3A - Strong Auth)
    Template injection but protected by authentication and limited to user's own data
    Attack path: request.args → preference_key → template_service.render_preference_template
    Protection: @login_required + user-scoped data only
    """
    preference_key = request.args.get('key', '')
    user_id = session.get('user_id')
    result = template_service.render_preference_template(user_id, preference_key)
    return jsonify({'preference': result})


# ==================== ADMIN ENDPOINTS ====================

@app.route('/api/admin/audit', methods=['GET'])
@admin_required
def admin_audit_logs():
    """
    VULN 6: FALSE POSITIVE - false_positive_protected (Subcategory 3A - Strong Auth/Authz)
    SQL injection but protected by strong admin authentication + authorization
    Attack path: request.args → date_filter → admin_service.get_audit_logs
    Protection: @admin_required (auth + role check) + admin-only functionality
    """
    date_filter = request.args.get('date', '')
    logs = admin_service.get_audit_logs(date_filter)
    return jsonify(logs)


@app.route('/api/admin/template/preview', methods=['POST'])
@admin_required
def admin_template_preview():
    """
    VULN 7: FALSE POSITIVE - false_positive_protected (Subcategory 3B - Defense in Depth)
    Template injection with multiple layers of protection
    Attack path: request.json → template_content → admin_service.preview_template
    Protection: @admin_required + CSRF + rate limiting + content sanitization
    """
    template_content = request.json.get('content', '')
    preview = admin_service.preview_template(template_content)
    return jsonify({'preview': preview})


# ==================== DEAD CODE / LEGACY ENDPOINTS ====================

@app.route('/api/legacy/import', methods=['POST'])
def legacy_import_data():
    """
    VULN 8: MIXED SCENARIO - Multiple paths with different classifications
    
    This endpoint demonstrates a complex testing scenario with 3 attack paths:
    
    PATH 1 (DEAD): legacy_mode_enabled branch → execute_legacy_query() (unreachable)
    PATH 2 (LIVE but SANITIZED): validation → _process_modern_import_with_query() (protected)
    PATH 3 (DEAD): admin_legacy_mode branch → _process_admin_legacy_import() (unreachable)
    
    Tests the scanner's ability to:
    - Analyze multiple paths independently
    - Classify each path's viability (VULNERABLE/PROTECTED/DEAD_CODE)
    - Make overall assessment: FALSE POSITIVE (all live paths are sanitized, dead paths unreachable)
    
    Attack paths: 
      - request.json → import_data → legacy_service.process_legacy_import
      - Path 1: → execute_legacy_query (DEAD CODE)
      - Path 2: → _validate_import_data → _process_modern_import_with_query (LIVE + SANITIZED)
      - Path 3: → _process_admin_legacy_import (DEAD CODE)
    """
    import_data = request.json.get('data', '')
    is_admin = request.json.get('is_admin', False)
    import_type = request.json.get('type', 'standard')
    result = legacy_service.process_legacy_import(import_data, is_admin, import_type)
    return jsonify(result)


# ==================== INTERNAL/UNUSED ROUTES (NOT REGISTERED) ====================

def internal_diagnostic_endpoint():
    """
    This endpoint is defined but NEVER registered with Flask
    It should be detected as dead code by the analyzer
    """
    diagnostic_query = request.args.get('query', '')
    return db_service.run_diagnostic_query(diagnostic_query)


# ==================== HEALTH CHECK ====================

@app.route('/health', methods=['GET'])
def health_check():
    """Health check endpoint"""
    return jsonify({'status': 'healthy', 'service': 'python_banking'})


if __name__ == '__main__':
    app.run(debug=False, host='0.0.0.0', port=5000)
