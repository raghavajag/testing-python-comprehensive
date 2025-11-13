import sqlite3

class DatabaseHelper:
    def __init__(self):
        self.connection = sqlite3.connect(':memory:')
    
    def execute_raw_query(self, query):
        cursor = self.connection.cursor()
        cursor.execute(query)  # VULNERABLE SINK
        return cursor.fetchall()
    
    def execute_parameterized_query(self, query, params):
        cursor = self.connection.cursor()
        cursor.execute(query, params)  # SAFE - Parameterized
        return cursor.fetchall()
