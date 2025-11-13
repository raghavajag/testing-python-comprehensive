"""
Legacy Service - Dead Code Examples
====================================

Contains deprecated and unreachable code with vulnerabilities:
1. Legacy import processor with dead code path
2. Deprecated functions that are never called
3. Functions that lead to dead code sinks

These demonstrate false_positive_dead_code classification
"""

from typing import Dict, Any
from services.database_service import DatabaseService


class LegacyService:
    """Legacy service with dead code vulnerabilities"""
    
    def __init__(self):
        self.db_service = DatabaseService()
        self.legacy_mode_enabled = False  # Always False - feature deprecated
    
    # ==================== VULN 8: FALSE POSITIVE - Dead Code Path ====================
    
    def process_legacy_import(self, import_data: str) -> Dict[str, Any]:
        """
        VULN 8: FALSE POSITIVE - false_positive_dead_code
        
        This function is called from /api/legacy/import endpoint,
        BUT it has a dead code path that never executes
        
        The legacy_mode_enabled flag is always False and can never be changed,
        so the vulnerable execute_legacy_query() is never reached
        
        Attack path: request.json → import_data → process_legacy_import → 
                     execute_legacy_query (DEAD CODE BRANCH)
        
        Protection: Dead code - the vulnerable branch is unreachable
        """
        # Check legacy mode (always False - deprecated feature)
        if self.legacy_mode_enabled:
            # DEAD CODE BRANCH - this is never executed
            # legacy_mode_enabled is always False and immutable
            return self.execute_legacy_query(import_data)
        
        # Live code path - safe processing
        return self._process_modern_import(import_data)
    
    def execute_legacy_query(self, legacy_data: str) -> Dict[str, Any]:
        """
        DEAD CODE FUNCTION - never called due to legacy_mode_enabled = False
        
        This contains a SQL injection vulnerability but is completely unreachable
        The process_legacy_import() function never enters the if-branch
        """
        # This is dead code - SQL injection sink never reached
        result = self.db_service.execute_legacy_query(legacy_data)
        return result
    
    def _process_modern_import(self, import_data: str) -> Dict[str, Any]:
        """
        Modern, safe import processing
        This is the actual live code path that executes
        """
        # Safe processing logic
        return {
            'status': 'success',
            'message': 'Data processed using modern import system',
            'data': import_data[:100]  # Truncate for safety
        }
    
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
