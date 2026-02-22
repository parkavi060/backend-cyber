import time
from flask import request, current_app, g
from datetime import datetime

def setup_request_logging(app):
    """
    Registers before/after request handlers for request logging.
    """
    
    @app.before_request
    def start_timer():
        g.start_time = time.time()

    @app.after_request
    def log_request(response):
        # Skip static files and health checks
        if request.path.startswith('/static') or request.path == '/api/admin/system-health':
            return response

        now = datetime.utcnow()
        duration = round((time.time() - g.start_time) * 1000, 2)
        
        log_data = {
            "timestamp": now,
            "method": request.method,
            "path": request.path,
            "status": response.status_code,
            "duration_ms": duration,
            "ip": request.remote_addr,
            "user_agent": request.user_agent.string
        }

        # Log to file
        current_app.logger.info(
            f"{request.remote_addr} - {request.method} {request.path} {response.status_code} ({duration}ms)"
        )

        # Log to MongoDB (async-lite: just insert)
        try:
            current_app.db.request_logs.insert_one(log_data)
        except Exception as e:
            # Don't fail the request if logging fails
            pass
            
        return response
