from repositories.account_repository import AccountRepository
from services.validation_service import ValidationService
from utils.input_processor import InputProcessor

class AccountService:
    def __init__(self):
        self.repository = AccountRepository()
        self.validator = ValidationService()
        self.processor = InputProcessor()
    
    # VULN 1 PATH (5 functions): controller -> service -> processor -> repository -> db_helper
    def search_by_name(self, name):
        processed_name = self.processor.process_search_term(name)
        return self.repository.search_accounts_raw(processed_name)
    
    # VULN 2 PATH (5 functions): controller -> service -> validator -> repository -> db_helper  
    def find_by_id_safe(self, account_id):
        validated_id = self.validator.validate_numeric(account_id)
        return self.repository.find_by_id_parameterized(validated_id)
    
    # VULN 3 PATH (5 functions): controller -> service -> validator -> repository -> db_helper
    def lookup_by_type(self, account_type):
        validated_type = self.validator.validate_account_type(account_type)
        return self.repository.lookup_by_validated_type(validated_type)
    
    # VULN 4 PATH (4 functions): controller -> service -> repository -> db_helper
    def admin_raw_search(self, query):
        return self.repository.admin_search_raw(query)
    
    # VULN 5 PATH A (4 functions): controller -> service -> repository -> db_helper
    def generate_detailed_report(self, account_id):
        return self.repository.get_detailed_report(account_id)
    
    # VULN 5 PATH B (dead - 4 functions): controller -> service -> repository -> db_helper
    def generate_legacy_report(self, account_id):
        return self.repository.get_legacy_report(account_id)
    
    # VULN 6 PATH (dead - 4 functions): controller -> service -> repository -> db_helper
    def legacy_search(self, search_query):
        return self.repository.legacy_search_raw(search_query)
