from __future__ import unicode_literals

import os

# User can change path to log on his own
import argparse
from pathlib2 import Path

PACKET_LENGTH_PERMISSION_NAME = "CAN_SET_PACKET_LENGTH"
LOG_FILE = os.path.join(os.path.abspath(os.path.pardir), 'log', 'bgpfs2acl.log')

# creating path to store logs if it doesn't exist
if not os.path.exists(os.path.dirname(LOG_FILE)):
    os.makedirs(os.path.dirname(LOG_FILE))

log_config = {
    'version': 1,
    'disable_existing_loggers': False,

    'formatters': {
        'verbose': {
            'format': ('bgpfs2acl: { "loggerName":"%(name)s", "asciTime":"%(asctime)s", "pathName":"%(pathname)s", '
                       '"logRecordCreationTime":"%(created)f", "functionName":"%(funcName)s", "levelNo":"%(levelno)s", '
                       '"lineNo":"%(lineno)d", "levelName":"%(levelname)s", "message":"%(message)s"}'),
        },
        'simple': {
            'format': '%(asctime)s - %(levelname)s - %(message)s',
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

__log_level_names = ('CRITICAL', 'ERROR', 'WARNING', 'INFO', 'DEBUG')
__default_syslog_level = 'WARNING'

__default_config_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'parameters.ini')

parser = argparse.ArgumentParser(description='BGP FlowSpec to ACL converter')
# parser.add_argument('-c', '--my-config', is_config_file=True, help='config file path')
parser.add_argument("--upd-frequency", dest='upd_frequency', default=30, type=int,
                    help="sets checking flowspec updates frequency, default value 30 sec")
parser.add_argument("--fs-start-seq", help="Define the first sequence to add ACEs generated from Flowspec "
                                           "(<1-2147483643>). Default - 100500.",
                    type=int, default=100500, dest='fs_start_seq')
parser.add_argument("--revert", help="Start script in clean up mode", action="store_true")
parser.add_argument("--default-acl-name", type=str, default='bgpfs2acl-ipv4',
                    dest='default_acl_name', help="Define default ACL name")
parser.add_argument("--router-host", type=str, default='127.0.0.1', dest='router_host')
parser.add_argument("--router-port", type=int, default='57722', dest='router_port')
parser.add_argument("--router-user", type=str, default='bgpfs2acl', dest='user')
parser.add_argument("--router-password", type=str, default='', dest='password')

parser.add_argument("--syslog-host", type=str, dest='syslog_host')
parser.add_argument("--syslog-port", type=int, dest='syslog_port')
parser.add_argument("--syslog-filename", type=Path, dest='syslog_filename')
parser.add_argument("--syslog-loglevel", type=str, default=__default_syslog_level, choices=__log_level_names)

# Todo add fix line numbers;
# Todo add verbose story;

app_config = {}
def set_app_config():
    app_config = parser.parse_args()
    return app_config

