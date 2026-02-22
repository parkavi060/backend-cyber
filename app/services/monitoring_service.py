import psutil
import time
from datetime import datetime
from flask import current_app

def get_system_metrics():
    """
    Retrieves real system metrics using psutil and MongoDB info.
    """
    start_time = getattr(current_app, 'start_time', time.time())
    uptime_seconds = time.time() - start_time
    
    # DB Latency (Ping)
    db_latency = "N/A"
    try:
        start_ping = time.time()
        current_app.db.command("ping")
        db_latency = f"{round((time.time() - start_ping) * 1000, 2)}ms"
    except:
        pass

    # Uptime format
    hours, rem = divmod(uptime_seconds, 3600)
    minutes, seconds = divmod(rem, 60)
    uptime_str = f"{int(hours)}h {int(minutes)}m"

    metrics = {
        "cards": [
            {
                "label": "CPU USAGE",
                "value": f"{psutil.cpu_percent()}%",
                "status": "normal" if psutil.cpu_percent() < 80 else "warning"
            },
            {
                "label": "MEMORY",
                "value": f"{round(psutil.virtual_memory().used / (1024**3), 2)}GB / {round(psutil.virtual_memory().total / (1024**3), 2)}GB",
                "status": "normal" if psutil.virtual_memory().percent < 80 else "warning"
            },
            {
                "label": "DB LATENCY",
                "value": db_latency,
                "status": "normal"
            },
            {
                "label": "API UPTIME",
                "value": uptime_str,
                "status": "normal"
            }
        ],
        "system": {
            "platform": psutil.os.name,
            "boot_time": datetime.fromtimestamp(psutil.boot_time()).strftime("%Y-%m-%d %H:%M:%S"),
            "cpu_count": psutil.cpu_count(),
            "memory_percent": psutil.virtual_memory().percent
        }
    }
    
    return metrics
