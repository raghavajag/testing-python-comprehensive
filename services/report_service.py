from flask import render_template_string
import html

class ReportService:
    # VULN 7 PATH (4 functions): controller -> service -> sanitizer -> render_template_string
    def generate_safe_report(self, template_data):
        escaped_data = html.escape(template_data)
        template_str = f"<h1>Report</h1><div>{escaped_data}</div>"
        return render_template_string(template_str)
    
    # VULN 8 PATH (3 functions): controller -> service -> render_template_string
    def generate_custom_report(self, user_template):
        return render_template_string(user_template)
