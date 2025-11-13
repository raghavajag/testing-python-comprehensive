from flask import Blueprint, request, render_template_string
from services.report_service import ReportService
from utils.auth_decorators import login_required

report_bp = Blueprint('reports', __name__)
report_service = ReportService()

# VULN 7: FALSE POSITIVE - Sanitized (HTML Escaping)
@report_bp.route('/generate', methods=['POST'])
@login_required
def generate_report():
    template_data = request.json.get('template', '')
    return report_service.generate_safe_report(template_data)

# VULN 8: TRUE POSITIVE - SSTI (must_fix)
@report_bp.route('/custom', methods=['POST'])
def generate_custom_report():
    user_template = request.json.get('template', '')
    return report_service.generate_custom_report(user_template)
