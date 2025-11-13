"""
Legacy Service - Dead Code and Mixed Path Examples
===================================================

Contains deprecated and unreachable code with vulnerabilities:
1. Legacy import processor with MIXED PATHS:
   - Path 1: Dead code path (never executes)
   - Path 2: Live path with validation (sanitized)
   - Path 3: Admin-only path (protected)
2. Deprecated functions that are never called
3. Functions that lead to dead code sinks

These demonstrate false_positive_dead_code classification AND mixed scenarios
"""

from typing import Dict, Any
from services.database_service import DatabaseService
from services.validation_service import ValidationService


class LegacyService:
    """Legacy service with dead code vulnerabilities and mixed path scenarios"""
    
    def __init__(self):
        self.db_service = DatabaseService()
        self.validation_service = ValidationService()
        self.legacy_mode_enabled = False  # Always False - feature deprecated
        self.admin_legacy_mode = False  # Never set to True anywhere
    
    # ==================== VULN 8: MIXED SCENARIO - Multiple Paths with Different Classifications ====================
    
    def process_legacy_import(self, import_data: str, is_admin: bool = False, import_type: str = "standard") -> Dict[str, Any]:
        """
        VULN 8: MIXED SCENARIO - Multiple attack paths with different classifications
        
        This function demonstrates a complex scenario with 3 attack paths:
        
        PATH 1 (DEAD CODE): legacy_mode_enabled branch
            → execute_legacy_query() 
            → SQL injection sink (UNREACHABLE)
            Classification: DEAD_CODE
            
        PATH 2 (SANITIZED): standard import with validation
            → _validate_import_data()
            → _process_modern_import_with_query()
            → SQL injection sink (PROTECTED by validation)
            Classification: SECURE/PROTECTED
            
        PATH 3 (DEAD CODE): admin legacy mode branch
            → _process_admin_legacy_import()
            → SQL injection sink (UNREACHABLE - admin_legacy_mode always False)
            Classification: DEAD_CODE
        
        OVERALL: Must be classified as FALSE POSITIVE because:
        - Path 1: Dead code (never executes)
        - Path 2: Live but sanitized (validation protects)
        - Path 3: Dead code (never executes)
        
        This tests the LLM's ability to:
        1. Analyze multiple paths independently
        2. Classify per-path viability correctly
        3. Make overall vulnerability assessment based on worst-case LIVE path
        4. Recognize that all exploitable paths are either dead or protected
        """
        
        # PATH 1: Dead code branch - legacy_mode_enabled is always False
        if self.legacy_mode_enabled:
            # ⚰️ DEAD CODE BRANCH - never executes
            # legacy_mode_enabled is immutable and always False
            return self.execute_legacy_query(import_data)
        
        # PATH 3: Another dead code branch - admin_legacy_mode never True
        if is_admin and self.admin_legacy_mode:
            # ⚰️ DEAD CODE BRANCH - never executes
            # admin_legacy_mode is never set to True anywhere in codebase
            return self._process_admin_legacy_import(import_data)
        
        # PATH 2: LIVE CODE PATH with validation (the only reachable path)
        # This path is live but PROTECTED by validation
        try:
            validated_data = self._validate_import_data(import_data)
            return self._process_modern_import_with_query(validated_data, import_type)
        except ValueError as e:
            return {'status': 'error', 'message': str(e)}
    
    def _validate_import_data(self, data: str) -> str:
        """
        Validates import data before processing (PATH 2 protection)
        Uses strict allowlist validation to prevent SQL injection
        """
        # Allowlist: only alphanumeric and underscores allowed
        if not self.validation_service.validate_alphanumeric(data):
            raise ValueError("Import data must be alphanumeric")
        return data
    
    def _process_modern_import_with_query(self, validated_data: str, import_type: str) -> Dict[str, Any]:
        """
        PATH 2: Live path that executes SQL query but with validated input
        This demonstrates a sink that is reachable but protected by validation
        
        The validated_data has been sanitized by _validate_import_data()
        which ensures only alphanumeric characters, preventing SQL injection
        """
        # This LOOKS vulnerable but validated_data is sanitized
        query = f"INSERT INTO import_log (data, type) VALUES ('{validated_data}', '{import_type}')"
        cursor = self.db_service.conn.cursor()
        try:
            cursor.execute(query)  # VULN 8 PATH 2: SQL INJECTION SINK (but validated input)
            self.db_service.conn.commit()
            return {'status': 'success', 'message': 'Data imported using modern system', 'data': validated_data}
        except Exception as e:
            return {'status': 'error', 'message': f'Import failed: {str(e)}'}
    
    def execute_legacy_query(self, legacy_data: str) -> Dict[str, Any]:
        """
        PATH 1: DEAD CODE FUNCTION - never called due to legacy_mode_enabled = False
        
        This contains a SQL injection vulnerability but is completely unreachable
        The process_legacy_import() function never enters the if-branch
        """
        # This is dead code - SQL injection sink never reached
        query = f"INSERT INTO users (username, email) VALUES ('{legacy_data}', 'legacy@example.com')"
        cursor = self.db_service.conn.cursor()
        cursor.execute(query)  # VULN 8 PATH 1: SQL INJECTION SINK (but dead code)
        self.db_service.conn.commit()
        return {'status': 'inserted', 'data': legacy_data}
    
    def _process_admin_legacy_import(self, import_data: str) -> Dict[str, Any]:
        """
        PATH 3: DEAD CODE FUNCTION - never called due to admin_legacy_mode = False
        
        This is another unreachable path with SQL injection
        """
        # This is dead code - SQL injection sink never reached
        query = f"INSERT INTO admin_imports (data) VALUES ('{import_data}')"
        cursor = self.db_service.conn.cursor()
        cursor.execute(query)  # VULN 8 PATH 3: SQL INJECTION SINK (but dead code)
        self.db_service.conn.commit()
        return {'status': 'admin_import', 'data': import_data}
    
    # ==================== ADDITIONAL DEAD CODE EXAMPLES ====================
    
    def deprecated_batch_processor(self, batch_data: str) -> Dict[str, Any]:
        """
        DEAD CODE - This function is never called from anywhere
        
        There are no references to this function in the codebase
        It should be detected as dead code by static analysis
        """
        # Dead code with SQL injection
        query = f"INSERT INTO legacy_batches VALUES ('{batch_data}')"
        cursor = self.db_service.conn.cursor()
        cursor.execute(query)  # Dead code SQL injection sink
        return {'status': 'processed'}
    
    def old_migration_handler(self, migration_sql: str) -> bool:
        """
        DEAD CODE - Deprecated migration system
        
        This was used in version 1.0 but has been completely replaced
        No code paths lead here anymore
        """
        # Dead code with SQL injection
        cursor = self.db_service.conn.cursor()
        cursor.execute(migration_sql)  # Dead code SQL injection sink
        self.db_service.conn.commit()
        return True
    
    def enable_legacy_mode(self, admin_password: str) -> bool:
        """
        DEAD CODE - This function exists but is never called
        
        Even if it were called, it doesn't actually enable legacy mode
        The legacy_mode_enabled flag is instance-level and this creates a new instance
        """
        if admin_password == "deprecated_feature":
            # This doesn't actually enable anything because it's on a different instance
            temp_service = LegacyService()
            temp_service.legacy_mode_enabled = True
            return True
        return False
