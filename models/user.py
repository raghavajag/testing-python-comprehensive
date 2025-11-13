"""
User Model - ORM Examples
=========================

Demonstrates safe ORM patterns that should NOT be flagged as vulnerable
"""

from typing import Optional, Dict, Any


class User:
    """User model with ORM-style query methods"""
    
    def __init__(self, db_connection):
        self.conn = db_connection
    
    def find_by_id(self, user_id: int) -> Optional[Dict[str, Any]]:
        """
        Safe ORM-style query using parameterized queries
        This should NOT be flagged as vulnerable
        """
        query = "SELECT * FROM users WHERE id = ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (user_id,))
        result = cursor.fetchone()
        if result:
            return {
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3]
            }
        return None
    
    def find_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """
        Safe ORM-style query using parameterized queries
        This should NOT be flagged as vulnerable
        """
        query = "SELECT * FROM users WHERE email = ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (email,))
        result = cursor.fetchone()
        if result:
            return {
                'id': result[0],
                'username': result[1],
                'email': result[2],
                'role': result[3]
            }
        return None
    
    def create_user(self, username: str, email: str, role: str = 'user') -> int:
        """
        Safe ORM-style insert using parameterized queries
        This should NOT be flagged as vulnerable
        """
        query = "INSERT INTO users (username, email, role) VALUES (?, ?, ?)"
        cursor = self.conn.cursor()
        cursor.execute(query, (username, email, role))
        self.conn.commit()
        return cursor.lastrowid
    
    def update_user(self, user_id: int, **kwargs) -> bool:
        """
        Safe ORM-style update using parameterized queries
        This should NOT be flagged as vulnerable
        """
        allowed_fields = ['username', 'email', 'role']
        updates = []
        params = []
        
        for field, value in kwargs.items():
            if field in allowed_fields:
                updates.append(f"{field} = ?")
                params.append(value)
        
        if not updates:
            return False
        
        params.append(user_id)
        query = f"UPDATE users SET {', '.join(updates)} WHERE id = ?"
        cursor = self.conn.cursor()
        cursor.execute(query, tuple(params))
        self.conn.commit()
        return cursor.rowcount > 0


class Transaction:
    """Transaction model with ORM-style query methods"""
    
    def __init__(self, db_connection):
        self.conn = db_connection
    
    def find_by_user(self, user_id: int) -> list:
        """
        Safe ORM-style query using parameterized queries
        This should NOT be flagged as vulnerable
        """
        query = "SELECT * FROM transactions WHERE user_id = ?"
        cursor = self.conn.cursor()
        cursor.execute(query, (user_id,))
        results = cursor.fetchall()
        return [
            {
                'id': r[0],
                'user_id': r[1],
                'amount': r[2],
                'description': r[3]
            }
            for r in results
        ]
    
    def create_transaction(self, user_id: int, amount: float, description: str) -> int:
        """
        Safe ORM-style insert using parameterized queries
        This should NOT be flagged as vulnerable
        """
        query = "INSERT INTO transactions (user_id, amount, description) VALUES (?, ?, ?)"
        cursor = self.conn.cursor()
        cursor.execute(query, (user_id, amount, description))
        self.conn.commit()
        return cursor.lastrowid
