import logging
import logging.config
import sys

def configure_logger(log_path, debug_mode=True):
    """Configures logging"""
    handlers = ['console'] # Always use console logging
    if not debug_mode:
        handlers.append('file')
    # handlers.append('file')

    logging.config.dictConfig({
        'version': 1,
        'disable_existing_loggers': False,  # Prevents disabling third-party loggers

        # Define formatters
        'formatters': {
            'default': {
                'format': '%(asctime)s %(levelname)s %(module)s %(funcName)s %(message)s',
                'datefmt': '%Y-%m-%d %H:%M:%S'
            }
        },

        # Define handlers (console and rotating file)
        'handlers': {
            'console': {
                'level': 'DEBUG',
                'class': 'logging.StreamHandler',
                'formatter': 'default',
                'stream': 'ext://sys.stdout'  # Logs to console
            },
            'file': {
                'level': 'DEBUG',
                'class': 'logging.handlers.RotatingFileHandler',
                'formatter': 'default',
                'filename': log_path,
                'maxBytes': 1024,  # 1KB max size
                'backupCount': 3  # Keep last 3 log files
            }
        },

        # Define loggers
        'loggers': {
            'default': {
                'level': 'DEBUG',
                'handlers': handlers,
                'propagate': False
            }
        }
    })

    return logging.getLogger("default")  