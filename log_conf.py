import os

# User can change path to log on his own
LOG_FILE = os.path.join(os.path.abspath(os.path.curdir), 'log', 'bgpfs2acl.log')

# creating path to store logs if it doesn't exist
if not os.path.exists(os.path.dirname(LOG_FILE)):
    os.makedirs(os.path.dirname(LOG_FILE))

LOG_CONFIG = {
    'version': 1,
    'disable_existing_loggers': True,

    'formatters': {
        'verbose': {
            'format': '%(levelname)s | %(asctime)s | %(module)s | %(process)d | %(thread)d | %(message)s',
        },
        'simple': {
            'format': '%(levelname)s: %(message)s',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
        'file': {
            'level': 'INFO',
            'class': 'logging.handlers.TimedRotatingFileHandler',
            'formatter': 'verbose',
            'filename': LOG_FILE,
            'when': 'D',
            'interval': 1,
            'backupCount': 7,
        }
    },
    'loggers': {
        '': {
            'handlers': ['console', 'file'],
            'propagate': True,
            'level': 'INFO',
        },
    }
}
