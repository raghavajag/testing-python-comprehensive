from flask import Blueprint, request, jsonify
from services.account_service import AccountService
from utils.auth_decorators import admin_required, csrf_protected, rate_limit

account_bp = Blueprint('accounts', __name__)
account_service = AccountService()

# VULN 1: TRUE POSITIVE - Must Fix (Direct SQL Injection)
@account_bp.route('/search', methods=['GET'])
def search_accounts():
    search_term = request.args.get('name', '')
    return jsonify(account_service.search_by_name(search_term))

# VULN 2: FALSE POSITIVE - Sanitized (Parameterized Query)
@account_bp.route('/find', methods=['GET'])
def find_account():
    account_id = request.args.get('id', '')
    return jsonify(account_service.find_by_id_safe(account_id))

# VULN 3: FALSE POSITIVE - Sanitized (Strict Validation)
@account_bp.route('/lookup', methods=['GET'])
def lookup_account():
    account_type = request.args.get('type', '')
    return jsonify(account_service.lookup_by_type(account_type))

# VULN 4: FALSE POSITIVE - Protected (Defense-in-Depth)
@account_bp.route('/admin/search', methods=['POST'])
@admin_required
@csrf_protected
@rate_limit(max_requests=10, window_seconds=60)
def admin_search():
    query = request.json.get('query', '')
    return jsonify(account_service.admin_raw_search(query))

# VULN 5: TRUE POSITIVE - Mixed Paths (must_fix with live+dead paths)
@account_bp.route('/report', methods=['GET'])
def generate_report():
    report_type = request.args.get('type', 'summary')
    account_id = request.args.get('account_id', '')
    
    if report_type == 'detailed':
        return jsonify(account_service.generate_detailed_report(account_id))
    elif report_type == 'legacy':
        return jsonify(account_service.generate_legacy_report(account_id))
    else:
        return jsonify({'summary': 'Safe summary report'})

# VULN 6: FALSE POSITIVE - Dead Code (never called)
def unused_legacy_search(search_query):
    return account_service.legacy_search(search_query)
