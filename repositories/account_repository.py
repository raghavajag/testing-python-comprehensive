from utils.database_helper import DatabaseHelper

class AccountRepository:
    def __init__(self):
        self.db = DatabaseHelper()
    
    # VULN 1: SQL Injection Sink
    def search_accounts_raw(self, name):
        query = f"SELECT * FROM accounts WHERE name = '{name}'"
        return self.db.execute_raw_query(query)
    
    # VULN 2: Safe - Parameterized query
    def find_by_id_parameterized(self, account_id):
        query = "SELECT * FROM accounts WHERE id = ?"
        return self.db.execute_parameterized_query(query, [account_id])
    
    # VULN 3: Safe - Validated input (allowlist)
    def lookup_by_validated_type(self, validated_type):
        query = f"SELECT * FROM accounts WHERE type = '{validated_type}'"
        return self.db.execute_raw_query(query)
    
    # VULN 4: Protected - Admin only
    def admin_search_raw(self, query):
        full_query = f"SELECT * FROM accounts WHERE {query}"
        return self.db.execute_raw_query(full_query)
    
    # VULN 5 PATH A: Live vulnerable path
    def get_detailed_report(self, account_id):
        query = f"SELECT * FROM account_details WHERE account_id = '{account_id}'"
        return self.db.execute_raw_query(query)
    
    # VULN 5 PATH B: Dead path
    def get_legacy_report(self, account_id):
        query = f"SELECT * FROM legacy_reports WHERE account_id = '{account_id}'"
        return self.db.execute_raw_query(query)
    
    # VULN 6: Dead code
    def legacy_search_raw(self, search_query):
        query = f"SELECT * FROM legacy_accounts WHERE {search_query}"
        return self.db.execute_raw_query(query)
