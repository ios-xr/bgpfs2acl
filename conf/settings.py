from __future__ import unicode_literals

import os

# User can change path to log on his own
LOG_FILE = os.path.join(os.path.abspath(os.path.pardir), 'log', 'bgpfs2acl.log')

# creating path to store logs if it doesn't exist
if not os.path.exists(os.path.dirname(LOG_FILE)):
    os.makedirs(os.path.dirname(LOG_FILE))

LOG_CONFIG = {
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'verbose': {
            'format': ('bgpfs2acl: { "loggerName":"%(name)s", "asciTime":"%(asctime)s", "pathName":"%(pathname)s", '
                       '"logRecordCreationTime":"%(created)f", "functionName":"%(funcName)s", "levelNo":"%(levelno)s", '
                       '"lineNo":"%(lineno)d", "time":"%(msecs)d", "levelName":"%(levelname)s", "message":"%('
                       'message)s"}'),
        },
        'simple': {
            'format': '%(asctime) - %(levelname)s - %(message)s',
        },
    },
    'handlers': {
        'console': {
            'level': 'INFO',
            'class': 'logging.StreamHandler',
            'formatter': 'simple',
        },
    },
    'loggers': {
        '': {
            'handlers': ['console'],  # you can add or remove log handlers here
            'propagate': True,
            'level': 'INFO',
        },
    }
}



