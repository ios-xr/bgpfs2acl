#!/usr/bin/env python
from __future__ import unicode_literals, print_function

import os
import re

import sys

import logging.config
import threading
from logging.handlers import SysLogHandler

from conf import settings
from conf.settings import log_config, app_config
from src.flowspec import FlowSpec
from src.func_lib import get_interfaces_md5
from src.access_list import AccessList, AccessListEntry
from src.xr_cmd_client import XRCmdClient, XRCmdExecError

logging.config.dictConfig(log_config)
logger = logging.getLogger(__name__)

HW_PROFILE_TCAM_CONF = ("hw-module profile tcam format access-list ipv4 src-addr dst-addr src-port dst-port proto "
                           "packet-length frag-bit port-range")


class BgpFs2AclTool:
    def __init__(self, xr_client):
        self.xr_client = xr_client

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
        interfaces = self.xr_client.xrcmd("sh running interface")
        interfaces_dict = {}
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

        for interface_name, feature_list in interfaces.iteritems():
            if pat.match(interface_name):
                filtered_interfaces.update({interface_name: feature_list})
        return filtered_interfaces

    def get_interfaces_by_acl_name(self, acl_name):
        result_dict = {}
        interfaces_dict = self.get_interfaces()
        for interface_name, feature_list in interfaces_dict.iteritems():
            for setting in feature_list:
                if setting.startswith('ipv4 access-group ' + acl_name + ' ingress'):
                    result_dict.update({interface_name: feature_list})
                    break
        return result_dict

    def get_flowspec(self):
        flowspec_ipv4 = self.xr_client.xrcmd('sh flowspec ipv4')

        if len(flowspec_ipv4) <= 1:
            return None

        return FlowSpec.from_config(flowspec_ipv4)

    def get_access_lists(self):
        acls_raw = self.xr_client.xrcmd('sh run ipv4 access-list')
        if len(acls_raw) <= 1:
            return None

        acls = AccessList.from_config(acls_raw)
        return acls

    def apply_conf(self, conf):
        if conf:
            return self.xr_client.xrapply_string(conf)


def convert_flowspec_to_acl_rules(flowspec):
    converted_rules = []
    for fs_rule in flowspec.rules:
        access_list_entries = [ace.rule for ace in AccessListEntry.from_flowspec_rule(fs_rule)]
        converted_rules.extend(access_list_entries)
    return converted_rules


def run(bgpfs2acl_tool):
    threading.Timer(app_config.upd_frequency, run, [bgpfs2acl_tool]).start()
    to_apply = ''
    flowspec = bgpfs2acl_tool.get_flowspec()
    access_lists = bgpfs2acl_tool.get_access_lists()
    filtered_interfaces = bgpfs2acl_tool.get_interfaces(filter_regx='^interface (Gig|Ten|Twe|Fo|Hu).*')

    if flowspec is None:
        logger.warning('Flowspec is empty/was not found.')
        if bgpfs2acl_tool.cached_fs_md5:
            logger.warning('Removing fs rules from access-lists...')
            for acl in access_lists:
                acl.remove_flowspec()
                remove_fs_conf = acl.get_changes_config()
                if remove_fs_conf:
                    to_apply = ''.join([to_apply, remove_fs_conf])

            bgpfs2acl_tool.cached_fs_md5 = None

    else:
        filtered_interfaces_md5 = get_interfaces_md5(filtered_interfaces)
        if flowspec.md5 != bgpfs2acl_tool.cached_fs_md5 \
                or filtered_interfaces_md5 != bgpfs2acl_tool.cached_filtered_interfaces_md5:
            bound_acls = set()
            pat = re.compile(r'ipv4 access-group (.*) ingress')
            to_apply_default_acl = []
            for interface, feature_list in filtered_interfaces.iteritems():
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

            updated_interfaces = bgpfs2acl_tool.get_interfaces(filter_regx='^interface (Gig|Ten|Twe|Fo|Hu).*')
            updated_interfaces_md5 = get_interfaces_md5(updated_interfaces)
            bgpfs2acl_tool.cached_filtered_interfaces_md5 = updated_interfaces_md5

    if to_apply:
        bgpfs2acl_tool.apply_conf(to_apply)


def clean_acls(bgpfs2acl_tool):
    logger.info('###### Reverting applied converted flowspec rules... ######')
    access_lists = bgpfs2acl_tool.get_access_lists()
    to_apply = ''
    for acl in access_lists:
        acl.remove_flowspec()
        apply_config = acl.get_changes_config()
        if apply_config:
            to_apply = '\n'.join([to_apply, apply_config])
    if to_apply:
        bgpfs2acl_tool.apply_conf(to_apply)
    logger.info("###### Script execution was complete ######")


def setup_syslog():
    root_logger = logging.getLogger()
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
        handler.setLevel(logging.INFO)
        root_logger.addHandler(handler)


def check_hw_module_config(xr_cmd_client):
    hw_module_cmd = "sh run {}".format(HW_PROFILE_TCAM_CONF)
    res = xr_cmd_client.xrcmd(hw_module_cmd)
    if res[0].startswith("No such configuration item(s)"):
        setattr(settings, settings.PACKET_LENGTH_PERMISSION_NAME, False)
    elif res[0].startswith(HW_PROFILE_TCAM_CONF):
        setattr(settings, settings.PACKET_LENGTH_PERMISSION_NAME, True)


def main():
    setup_syslog()
    logger.info("###### Starting BGPFS2ACL RUN on XR based device ######")
    xr_cmd_client = XRCmdClient(app_config.user, app_config.password, app_config.router_host, app_config.router_port)
    bgpfs2acl_tool = BgpFs2AclTool(xr_client=xr_cmd_client)

    try:
        if app_config.revert:
            clean_acls(bgpfs2acl_tool)
            sys.exit()

        check_hw_module_config(xr_cmd_client)
        run(bgpfs2acl_tool)
    except XRCmdExecError as err:
        logger.error(str(err))


if __name__ == "__main__":
    main()
