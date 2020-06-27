#!/usr/bin/env python
from __future__ import unicode_literals, print_function

import argparse
import re

import sys
import threading

import logging.config
import log_conf
from access_list import AccessList
from flowspec import FlowSpec
from func_lib import get_interfaces_md5
from xr_cmd_client import XRCmdClient

logging.config.dictConfig(log_conf.LOG_CONFIG)
logger = logging.getLogger(__name__)


class BgpFs2AclTool:
    def __init__(self, xr_client, default_acl_name, fs_start_seq):
        self.xr_client = xr_client

        if not (0 < len(default_acl_name) <= 65):
            raise ValueError('ACL name {} is out length range'.format(default_acl_name))
        self.default_acl_name = default_acl_name

        self.fs_start_seq = fs_start_seq

        self.cached_fs_md5 = None
        self.cached_acl_md5 = None
        self.cached_interfaces_md5 = None

    def get_interfaces(self, include_shutdown=False, filter_regx=None):
        """
        Returns XR interfaces dict, where a key is an 'interface ...' line, and a value is a list of applied
        features
        :param include_shutdown:
        :param filter_regx:
        :return:
        """
        logger.info("Getting Interfaces")
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


def run(bgpfs2acl_tool):
    # threading.Timer(frequency, run, [bgpfs2acl_tool]).start()
    to_apply = ''
    flowspec = bgpfs2acl_tool.get_flowspec()
    access_lists = bgpfs2acl_tool.get_access_lists()
    filtered_interfaces = bgpfs2acl_tool.get_interfaces(filter_regx='^interface (Gig|Ten|Twe|Fo|Hu).*')

    if flowspec is None:
        if bgpfs2acl_tool.cached_fs_md5:
            for acl in access_lists:
                acl.remove_flowspec()
                remove_fs_conf = acl.get_changes_config()
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
                default_acl = [acl for acl in access_lists if acl.name == bgpfs2acl_tool.default_acl_name]
                if not default_acl:
                    access_lists.append(AccessList(bgpfs2acl_tool.default_acl_name))
                bound_acls.add(bgpfs2acl_tool.default_acl_name)

            for acl in access_lists:
                if acl.name in bound_acls:
                    acl.apply_flowspec(flowspec, bgpfs2acl_tool.fs_start_seq)
                    acl_changes_config = acl.get_changes_config()
                    to_apply = '\n'.join([to_apply, acl_changes_config])

            for interface in to_apply_default_acl:
                ingress_acl_feature = 'ipv4 access-group {} ingress'.format(bgpfs2acl_tool.default_acl_name)
                to_apply = '\n'.join([to_apply, interface, ingress_acl_feature])

            bgpfs2acl_tool.cached_fs_md5 = flowspec.md5

            updated_interfaces = bgpfs2acl_tool.get_interfaces(filter_regx='^interface (Gig|Ten|Twe|Fo|Hu).*')
            updated_interfaces_md5 = get_interfaces_md5(updated_interfaces)
            bgpfs2acl_tool.cached_filtered_interfaces_md5 = updated_interfaces_md5

    if to_apply:
        bgpfs2acl_tool.apply_conf(to_apply)


def clean_script_actions(bgpfs2acl_tool):
    logger.info('###### Reverting applied acl rules... ######')
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


if __name__ == "__main__":
    logger.info("###### Starting BGPFS2ACL RUN on XR based device ######")

    parser = argparse.ArgumentParser(description='BGP FlowSpec to ACL converter')
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="increase output verbosity")
    parser.add_argument("-f", "--frequency", dest='frequency', default=30, type=int,
                        help="set script execution frequency, default value 30 sec")
    parser.add_argument("--fs_start_seq", help="Define the first sequence to add ACEs generated from Flowspec "
                                               "(<1-2147483643>). Default - 100500.",
                        type=int, default=100500)
    parser.add_argument("--revert", help="Start script in clean up mode", action="store_true")
    parser.add_argument("--default_acl_name", type=str, default='bgpfs2acl-ipv4',
                        dest='default_acl_name', help="Define default ACL name")

    parser.add_argument("--user", help="User for ssh connection", type=str, required=True)
    parser.add_argument("--password",
                        help="Password for ssh connection. Omit if use key authorization.",
                        type=str,
                        default='')
    parser.add_argument("--host", help="Router host address for ssh connection", type=str, default='127.0.0.1')
    parser.add_argument("--port", help="Router ssh port", type=int, default=57722)
    # Todo add fix line numbers;
    # Todo add verbose story;

    shell_args = parser.parse_args()

    xr_cmd_client = XRCmdClient(user=shell_args.user, password=shell_args.password, host=shell_args.host,
                                port=shell_args.port)

    conv_tool = BgpFs2AclTool(xr_client=xr_cmd_client, default_acl_name=shell_args.default_acl_name,
                              fs_start_seq=shell_args.fs_start_seq)

    if shell_args.revert:
        clean_script_actions(conv_tool)
        sys.exit()
    frequency = shell_args.frequency

    run(conv_tool)