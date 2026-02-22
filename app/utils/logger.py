import logging
import sys
from logging.handlers import RotatingFileHandler
import os

def setup_logger(app):
    """
    Configures logging for the application.
    - Console logging for development.
    - Rotating file logging for production.
    """
    log_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    
    # Console Handler
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(log_formatter)
    
    # File Handler
    if not os.path.exists('logs'):
        os.makedirs('logs')
        
    file_handler = RotatingFileHandler(
        'logs/app.log', maxBytes=10*1024*1024, backupCount=5
    )
    file_handler.setFormatter(log_formatter)
    
    # App Logger
    app.logger.addHandler(console_handler)
    app.logger.addHandler(file_handler)
    app.logger.setLevel(logging.INFO)
    
    app.logger.info("Logging initialized Successfully")
