"""
Database Service - SQL Injection Test Cases
============================================

Contains various SQL injection sinks with different protection levels:
1. Vulnerable direct SQL execution (TRUE POSITIVE)
2. Parameterized queries (FALSE POSITIVE - sanitized)
3. Validation-protected queries (FALSE POSITIVE - sanitized)
4. Dead code queries (FALSE POSITIVE - dead_code)
"""

import sqlite3
from typing import Dict, List, Any, Optional


class DatabaseService:
    """Database service with various SQL injection patterns"""
    
    def __init__(self):
        self.conn = self._create_connection()
    
    def _create_connection(self):
        """Create a database connection"""
        conn = sqlite3.connect(':memory:', check_same_thread=False)
        self._initialize_schema(conn)
        return conn
    
    def _initialize_schema(self, conn):
        """Initialize test database schema"""
        cursor = conn.cursor()
        cursor.execute('''CREATE TABLE IF NOT EXISTS users 
                         (id INTEGER PRIMARY KEY, username TEXT, email TEXT, role TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS transactions 
                         (id INTEGER PRIMARY KEY, user_id INTEGER, amount REAL, description TEXT)''')
        cursor.execute('''CREATE TABLE IF NOT EXISTS audit_logs 
                         (id INTEGER PRIMARY KEY, action TEXT, timestamp TEXT, user_id INTEGER)''')
        conn.commit()
    
    # ==================== VULN 1: TRUE POSITIVE - Direct SQL Injection ====================
    
    def search_transactions_vulnerable(self, search_term: str) -> List[Dict[str, Any]]:
        """
        VULN 1: TRUE POSITIVE - must_fix
        Direct string concatenation with no sanitization
        This is a clear SQL injection vulnerability
        """
        # VULNERABLE: Direct string interpolation
        query = f"SELECT * FROM transactions WHERE description LIKE '%{search_term}%'"
        cursor = self.conn.cursor()
        cursor.execute(query)  # VULN 1: SQL INJECTION SINK
        results = cursor.fetchall()
        return [{'id': r[0], 'user_id': r[1], 'amount': r[2], 'description': r[3]} for r in results]
    
    # ==================== VULN 2: FALSE POSITIVE - Validation Protected ====================
    
    def get_user_by_id_with_validation(self, validated_user_id: str) -> Optional[Dict[str, Any]]:
        """
        VULN 2: FALSE POSITIVE - false_positive_sanitized (Validation-Based)
        The user_id parameter has been validated by ValidationService.validate_user_id()
        which ensures it's strictly numeric using re.fullmatch(r'^[0-9]+$')
        
        Even though this uses string formatting, the validation makes it safe
        """
        # This LOOKS vulnerable, but validated_user_id is strictly numeric
        query = f"SELECT * FROM users WHERE id = {validated_user_id}"
        cursor = self.conn.cursor()
        cursor.execute(query)  # VULN 2: SQL INJECTION SINK (but protected by validation)
        result = cursor.fetchone()
        if result:
            return {'id': result[0], 'username': result[1], 'email': result[2], 'role': result[3]}
        return None
    
    # ==================== VULN 3: FALSE POSITIVE - Parameterized Query ====================
    
    def generate_report_parameterized(self, report_type: str, user_filter: str) -> List[Dict[str, Any]]:
        """
        VULN 3: FALSE POSITIVE - false_positive_sanitized (Direct Sanitization)
        Uses parameterized queries which prevent SQL injection
        This demonstrates proper ORM-style protection
        """
        # Safe: Using parameterized query
        query = "SELECT * FROM transactions WHERE user_id = ? AND description LIKE ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (user_filter, f'%{report_type}%'))  # VULN 3: SQL INJECTION SINK (but parameterized)
        results = cursor.fetchall()
        return [{'id': r[0], 'user_id': r[1], 'amount': r[2], 'description': r[3]} for r in results]
    
    # ==================== VULN 6: FALSE POSITIVE - Admin Protected ====================
    
    def get_audit_logs_by_date(self, date_filter: str) -> List[Dict[str, Any]]:
        """
        VULN 6: Part of admin-protected vulnerability chain
        This function is only called from AdminService.get_audit_logs()
        which is protected by @admin_required decorator
        
        Even though this has SQL injection, it's only accessible to admins
        """
        # VULNERABLE but admin-only access
        query = f"SELECT * FROM audit_logs WHERE timestamp LIKE '{date_filter}%'"
        cursor = self.conn.cursor()
        cursor.execute(query)  # VULN 6: SQL INJECTION SINK (but admin-protected)
        results = cursor.fetchall()
        return [{'id': r[0], 'action': r[1], 'timestamp': r[2], 'user_id': r[3]} for r in results]
    
    # ==================== DEAD CODE FUNCTIONS ====================
    
    def run_diagnostic_query(self, diagnostic_query: str) -> List[Dict[str, Any]]:
        """
        Part of dead code chain - called from internal_diagnostic_endpoint()
        which is never registered with Flask
        """
        query = f"SELECT * FROM users WHERE username = '{diagnostic_query}'"
        cursor = self.conn.cursor()
        cursor.execute(query)  # Dead code - never reached
        results = cursor.fetchall()
        return [{'id': r[0], 'username': r[1]} for r in results]
    
    def execute_legacy_query(self, legacy_data: str) -> Dict[str, Any]:
        """
        VULN 8: FALSE POSITIVE - dead_code
        Part of legacy service chain - this is deprecated and never actually called
        The LegacyService.process_legacy_import() has a dead code path
        """
        # This looks vulnerable but is in dead code
        query = f"INSERT INTO users (username, email) VALUES ('{legacy_data}', 'legacy@example.com')"
        cursor = self.conn.cursor()
        cursor.execute(query)  # VULN 8: SQL INJECTION SINK (but dead code)
        self.conn.commit()
        return {'status': 'inserted', 'data': legacy_data}
    
    # ==================== HELPER FUNCTIONS ====================
    
    def safe_query_with_orm(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Example of completely safe ORM-style query
        This should NOT be flagged as vulnerable
        """
        query = "SELECT * FROM users WHERE id = ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        if result:
            return {'id': result[0], 'username': result[1], 'email': result[2]}
        return None
