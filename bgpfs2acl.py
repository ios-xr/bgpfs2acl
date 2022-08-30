#!/usr/bin/env python
from __future__ import unicode_literals, print_function

import os
import re

import sys

from virtualenv import cli_run

from iosxr_grpc.cisco_grpc_client import CiscoGRPCClient

import logging.config
import threading
from logging.handlers import SysLogHandler

from conf import settings
from conf.settings import log_config, app_config, set_app_config
from src.flowspec import FlowSpec
from src.func_lib import get_interfaces_md5
from src.access_list import AccessList, AccessListEntry
from src.utils import convert_flowspec_to_acl_rules

# logging.config.dictConfig(log_config)
logger = logging.getLogger(__name__)

HW_PROFILE_TCAM_CONF = ("hw-module profile tcam format access-list ipv4 src-addr dst-addr src-port dst-port proto "
                        "packet-length frag-bit port-range")

DEFAULT_ACL_NAME = 'bgpfs2acl-ipv4'
FS_START_SEQUENCE = 100500
INT_REGEX = '(?=(^interface (Gig|Ten|Twe|Fo|Hu).*))(?!.*l2transport)'

class BgpFs2AclTool:
    def __init__(self, grpc_client):
        self.grpc_client = grpc_client
        self.cached_filtered_interfaces_md5 = None
        self.cached_fs_md5 = None

    def get_interfaces(self, include_shutdown=False, filter_regx=None):
        """
        Returns XR interfaces dict, where a key is an 'interface ...' line, and a value is a list of applied
        features
        :param include_shutdown:
        :param filter_regx:
        :return:
        """
        err, interfaces = self.grpc_client.showcmdtextoutput("sh running interface")
        if err:
            raise err.errors
        interfaces_dict = {}
        interfaces = interfaces.split('\n')
        for i, line in enumerate(interfaces):
            exclude = False
            if line.startswith('interface '):
                features_list = []
                j = i + 1
                while j < len(interfaces) and not interfaces[j].startswith('interface '):
                    if interfaces[j].strip() == 'shutdown' and not include_shutdown:
                        exclude = True
                        break
                    if interfaces[j].strip() != '!':
                        features_list.append(interfaces[j])
                    j += 1
                if not exclude:
                    interfaces_dict.update({line: features_list})
        if filter_regx:
            interfaces_dict = self._filter_interfaces(interfaces_dict, filter_regx)

        return interfaces_dict

    def _filter_interfaces(self, interfaces, regx):
        """Filter the list of interfaces by matching the regular expression."""
        filtered_interfaces = {}
        pat = re.compile(r'{}'.format(regx))

        for interface_name, feature_list in interfaces.items():
            if pat.match(interface_name):
                filtered_interfaces.update({interface_name: feature_list})
        return filtered_interfaces

    def get_interfaces_by_acl_name(self, acl_name):
        result_dict = {}
        interfaces_dict = self.get_interfaces()
        for interface_name, feature_list in interfaces_dict.items():
            for setting in feature_list:
                if setting.startswith('ipv4 access-group ' + acl_name + ' ingress'):
                    result_dict.update({interface_name: feature_list})
                    break
        return result_dict

    def get_flowspec(self):
        err, flowspec_ipv4 = self.grpc_client.showcmdtextoutput('sh flowspec ipv4')
        if err:
            raise Exception(err)

        if len(flowspec_ipv4) <= 1:
            return None

        return FlowSpec.from_config(flowspec_ipv4)

    def get_access_lists(self):
        err, acls_raw = self.grpc_client.showcmdtextoutput('sh run ipv4 access-list')
        if err:
            raise Exception(err)
        if len(acls_raw) <= 1:
            return None

        acls = AccessList.from_config(acls_raw)
        return acls

    def apply_conf(self, conf):
        if conf:
            response = self.grpc_client.cliconfig(conf)
            if response.errors:
                 raise Exception(response.errors)          
    
def run(bgpfs2acl_tool):
    threading.Timer(app_config.upd_frequency, run, [bgpfs2acl_tool]).start()
    logger.debug("start run")
    to_apply = ''
    flowspec = bgpfs2acl_tool.get_flowspec()
    access_lists = bgpfs2acl_tool.get_access_lists()
    filtered_interfaces = bgpfs2acl_tool.get_interfaces(filter_regx=INT_REGEX)
    if flowspec is None:
        logger.warning('Flowspec is empty/was not found.')
        for acl in access_lists:
            if acl.is_flowspec_applied():
                logger.warning('Removing fs rules from {} access-list...'.format(acl.name))
                acl.remove_flowspec()
                remove_fs_conf = acl.get_changes_config()
                if remove_fs_conf:
                    to_apply = '\n'.join([to_apply, remove_fs_conf])
        bgpfs2acl_tool.cached_fs_md5 = None

    else:
        filtered_interfaces_md5 = get_interfaces_md5(filtered_interfaces)
        logger.debug("Flowspec config: \n" + flowspec.config)
        logger.debug("HASH: " + flowspec.md5)
        if flowspec.md5 != bgpfs2acl_tool.cached_fs_md5 \
                or filtered_interfaces_md5 != bgpfs2acl_tool.cached_filtered_interfaces_md5:
            bound_acls = set()
            pat = re.compile(r'ipv4 access-group (.*) ingress')
            to_apply_default_acl = []
            for interface, feature_list in filtered_interfaces.items():
                f_match = False
                for feature in feature_list:
                    f_match = pat.match(feature)
                    if f_match:
                        bound_acls.add(f_match.group(1))
                        break
                if not f_match:
                    to_apply_default_acl.append(interface)

            if to_apply_default_acl:
                default_acl = [acl for acl in access_lists if acl.name == app_config.default_acl_name]
                if not default_acl:
                    access_lists.append(AccessList(app_config.default_acl_name))
                bound_acls.add(app_config.default_acl_name)

            converted_flowspec_rules = convert_flowspec_to_acl_rules(flowspec)
            for acl in access_lists:
                if acl.name in bound_acls:
                    acl.apply_flowspec(converted_flowspec_rules, app_config.fs_start_seq)
                    acl_changes_config = acl.get_changes_config()
                    if acl_changes_config:
                        to_apply = '\n'.join([to_apply, acl_changes_config])

            for interface in to_apply_default_acl:
                ingress_acl_feature = 'ipv4 access-group {} ingress'.format(app_config.default_acl_name)
                to_apply = '\n'.join([to_apply, interface, ingress_acl_feature])

            bgpfs2acl_tool.cached_fs_md5 = flowspec.md5

    if to_apply:
        bgpfs2acl_tool.apply_conf(to_apply)

        updated_interfaces = bgpfs2acl_tool.get_interfaces(filter_regx=INT_REGEX)
        updated_interfaces_md5 = get_interfaces_md5(updated_interfaces)
        bgpfs2acl_tool.cached_filtered_interfaces_md5 = updated_interfaces_md5


def clean_acls(bgpfs2acl_tool):
    logger.debug('###### Reverting applied converted flowspec rules... ######')
    access_lists = bgpfs2acl_tool.get_access_lists()
    to_apply = ''
    for acl in access_lists:
        acl.remove_flowspec()
        apply_config = acl.get_changes_config()
        if apply_config:
            to_apply = '\n'.join([to_apply, apply_config])
    if to_apply:
        bgpfs2acl_tool.apply_conf(to_apply)
    logger.debug("###### Script execution was complete ######")


def setup_syslog():
    root_logger = logging.getLogger()
    root_logger.setLevel(app_config.syslog_loglevel)
    formatter = logging.Formatter(
        ('bgpfs2acl: { "loggerName":"%(name)s", "asciTime":"%(asctime)s", "pathName":"%(pathname)s",'
         '"logRecordCreationTime":"%(created)f", "functionName":"%(funcName)s", "levelNo":"%(levelno)s",'
         '"lineNo":"%(lineno)d", "levelName":"%(levelname)s", "message":"%(message)s"}')
    )
    if any([all([app_config.syslog_host, app_config.syslog_port]), app_config.syslog_filename]):
        # add handler to the logger
        if all([app_config.syslog_host, app_config.syslog_port]):
            remote_handler = logging.handlers.SysLogHandler(
                address=(app_config.syslog_host,
                         app_config.syslog_port)
            )
            remote_handler.setFormatter(formatter)
            remote_handler.setLevel(app_config.syslog_loglevel)
            root_logger.addHandler(remote_handler)

        if app_config.syslog_filename:
            file_handler = logging.FileHandler(app_config.syslog_filename)
            file_handler.setFormatter(formatter)
            file_handler.setLevel(app_config.syslog_loglevel)
            root_logger.addHandler(file_handler)
    else:
        log_path = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'log', 'bgpfs2acl.log')
        if not os.path.exists(os.path.dirname(log_path)):
            os.makedirs(os.path.dirname(log_path))
        handler = logging.handlers.TimedRotatingFileHandler(log_path, when='D', interval=1, backupCount=7)
        handler.setFormatter(formatter)
        handler.setLevel(app_config.syslog_loglevel)
        root_logger.addHandler(handler)

def check_hw_module_config(grpc_client):
    hw_module_cmd = "sh run | in hw-module"
    err, res = grpc_client.showcmdtextoutput(hw_module_cmd)
    if err:
        raise Exception(err)
    hw_profile_tcam = res.strip().split('\n')[-1]
    if hw_profile_tcam != HW_PROFILE_TCAM_CONF:
        setattr(settings, settings.PACKET_LENGTH_PERMISSION_NAME, False)
    elif hw_profile_tcam == HW_PROFILE_TCAM_CONF:
        setattr(settings, settings.PACKET_LENGTH_PERMISSION_NAME, True)


def main():
    try:
        global app_config
        app_config = set_app_config()
        setup_syslog()
        grpc_timeout = 10
        client = CiscoGRPCClient(app_config.router_host, app_config.router_port, grpc_timeout, app_config.user, app_config.password)
        check_hw_module_config(client)
        bgpfs2acl_tool = BgpFs2AclTool(client)
    
        if app_config.revert:
            clean_acls(bgpfs2acl_tool)
            sys.exit()
        
        logger.debug("###### Starting BGPFS2ACL RUN on XR based device ######")
        run(bgpfs2acl_tool)
    except Exception as err:
        logger.error(str(err))


# if __name__ == "__main__":
#     main()

main()