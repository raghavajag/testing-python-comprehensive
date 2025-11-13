from functools import wraps
from flask import session, jsonify, request
import time

rate_limit_store = {}

def admin_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('is_admin'):
            return jsonify({"error": "Admin access required"}), 403
        return f(*args, **kwargs)
    return decorated_function

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if not session.get('user_id'):
            return jsonify({"error": "Authentication required"}), 401
        return f(*args, **kwargs)
    return decorated_function

def csrf_protected(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        csrf_token = request.headers.get('X-CSRF-Token')
        session_token = session.get('csrf_token')
        if not csrf_token or csrf_token != session_token:
            return jsonify({"error": "CSRF validation failed"}), 403
        return f(*args, **kwargs)
    return decorated_function

def rate_limit(max_requests=10, window_seconds=60):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id', 'anonymous')
            current_time = time.time()
            
            if user_id not in rate_limit_store:
                rate_limit_store[user_id] = []
            
            rate_limit_store[user_id] = [
                req_time for req_time in rate_limit_store[user_id]
                if current_time - req_time < window_seconds
            ]
            
            if len(rate_limit_store[user_id]) >= max_requests:
                return jsonify({"error": "Rate limit exceeded"}), 429
            
            rate_limit_store[user_id].append(current_time)
            return f(*args, **kwargs)
        return decorated_function
    return decorator
