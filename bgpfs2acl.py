#!/usr/bin/env python
from __future__ import unicode_literals, print_function

import argparse
import hashlib
import re
import socket

import sys
import threading
from itertools import product

from sortedcontainers import SortedDict
from pprint import pprint

from enum import Enum

import logging.config
import log_conf
from xr_cmd_client import XRCmdClient

logging.config.dictConfig(log_conf.LOG_CONFIG)
logger = logging.getLogger(__name__)

ALLOWED_PROTOCOLS = {
    'icmp': '1',
    'tcp': '6',
    'udp': '17',
}

ICMP_TYPE_CODENAMES = {
    'administratively-prohibited',
    'alternate-address',
    'conversion-error',
    'dod-host-prohibited',
    'dod-net-prohibited',
    'echo',
    'echo-reply',
    'general-parameter-problem',
    'host-isolated',
    'host-precedence-unreachable',
    'host-redirect',
    'host-tos-redirect',
    'host-tos-unreachable',
    'host-unknown',
    'host-unreachable',
    'information-reply',
    'information-request',
    'mask-reply',
    'mask-request',
    'mobile-redirect',
    'net-redirect',
    'net-tos-redirect',
    'net-tos-unreachable',
    'net-unreachable',
    'network-unknown',
    'no-room-for-option',
    'option-missing',
    'packet-too-big',
    'parameter-problem',
    'port-unreachable',
    'precedence-unreachable',
    'protocol-unreachable',
    'reassembly-timeout',
    'redirect',
    'router-advertisement',
    'router-solicitation',
    'source-quench',
    'source-route-failed',
    'time-exceeded',
    'timestamp-reply',
    'timestamp-request',
    'traceroute',
    'ttl-exceeded',
    'unreachable',
}

FLOWSPEC_START_REMARK = "FLOWSPEC RULES BEGIN. Do not add statements below this. Added automatically."
FLOWSPEC_END_REMARK = "FLOWSPEC RULES END"


class AccessListEntry:
    class Command(Enum):
        deny = 'deny'
        permit = 'permit'
        remark = 'remark'

    def __init__(self, command, protocol=None, source_ip=None, source_port=None, destination_ip=None,
                 destination_port=None, icmp_type=None, icmp_code=None, commentary=None):
        if command not in [c.value for c in AccessListEntry.Command.__members__.values()]:
            raise ValueError('Passed wrong ACL command: {}'.format(command))
        self._command = command

        if command == AccessListEntry.Command.remark.value:
            if commentary is None:
                raise ValueError("remark: no commentary provided.")
            self._commentary = commentary
            return

        self._protocol = self._validate_protocol(protocol, raise_exception=True)

        self._source_ip = self.validate_ip(source_ip)
        self._source_port = self.validate_rangeable_features(source_port)

        self._destination_ip = self.validate_ip(destination_ip)
        self._destination_port = self.validate_rangeable_features(destination_port)

        if self._protocol in ('icmp', '1') and icmp_type is not None:
            if ((isinstance(icmp_type, int) or icmp_type.isdigit()) and not 0 < int(icmp_type) < 256) \
                    and icmp_type not in ICMP_TYPE_CODENAMES:
                raise ValueError('Wrong icmp_type value: {}'.format(icmp_type))

        self._icmp_type = icmp_type

        if self._icmp_type and icmp_code is not None:
            if (isinstance(icmp_code, int) or icmp_code.isdigit()) and not 0 < int(icmp_code) < 256:
                raise ValueError('Wrong icmp_code value: {}'.format(icmp_code))
        self._icmp_code = icmp_code

    def _generate_rule(self):
        if self._command == AccessListEntry.Command.remark.value:
            return ' '.join([self._command, self._commentary])

        features = [self._command, self._protocol, self._source_ip, self._source_port,
                    self._destination_ip, self._destination_port]  # order is important

        features = [str(i) for i in features if i is not None]  # removed all empty fields

        keyword_features = []
        if self._icmp_type:
            keyword_features.append(self._icmp_type)
        if self._icmp_code:
            keyword_features.append(self._icmp_code)

        features.extend(keyword_features)

        return ' '.join(features)

    @classmethod
    def create_remark(cls, commentary):
        return cls(AccessListEntry.Command.remark.value, commentary=commentary)

    @staticmethod
    def _parse_ip(features_list):
        res = None
        if features_list[0] == 'host':
            res = ' '.join(features_list[:2])
            del features_list[:2]
        elif features_list == 'any':
            res = features_list.pop(0)
        else:
            ip_address = features_list[0].split('/')
            if len(ip_address) != 2 or int(ip_address[1]) > 32:
                raise ValueError('Bad ip format: {}'.format(features_list[0]))
            try:
                socket.inet_aton(ip_address[0])
            except socket.error:
                raise ValueError('Bad ip: {}'.format(ip_address))
            res = features_list.pop(0)
        return res

    @staticmethod
    def _parse_range(features_list):
        res = None
        if features_list[0] in ('eq', 'neq', 'gt', 'lt'):
            res = ' '.join(features_list[:2])
            del features_list[:2]
        elif features_list[0] == 'range':
            res = ' '.join(features_list[:3])
            del features_list[:3]

        return res

    @property
    def rule(self):
        return self._generate_rule()

    @staticmethod
    def validate_rangeable_features(values_list):
        if values_list is None:
            return values_list

        if values_list.startswith('range ') or values_list.startswith('eq '):
            to_check = values_list.split(' ')[1:]
            to_check = list(to_check)  # to be sure that this is list

            for value in to_check:
                if not value.isdigit() or not 0 < int(value) < 65536:
                    raise ValueError('Passed wrong feature value: {}'.format(values_list))

        return values_list

    @staticmethod
    def validate_ip(ip):
        if ip is None:
            return 'any'

        ip_components = ip.split('/')
        if len(ip_components) == 2 and ip_components[1] == '32':
            return 'host {}'.format(ip_components[0])

        if ip == 'any' or 'host ' in ip:
            return ip

        raise ValueError('Wrong ip parameter: {}'.format(ip))

    @staticmethod
    def _validate_protocol_list(protocols):
        if not protocols:
            return []

        validated = []
        for proto in protocols:
            proto = AccessListEntry._validate_protocol(proto, raise_exception=False)
            if proto:
                validated.append(proto)
        return validated

    @classmethod
    def from_flowspec_rule(cls, flowspec_rule):
        result_acl_rules = []

        init_args = {}

        action = AccessListEntry._parse_flowspec_action(flowspec_rule.actions)
        if not action:
            return []
        init_args['command'] = action

        init_args['source_ip'] = flowspec_rule.get_feature(FlowSpecRule.FeatureNames.source_ip.value)
        init_args['destination_ip'] = flowspec_rule.get_feature(FlowSpecRule.FeatureNames.destination_ip.value)

        protocol_list = AccessListEntry._parse_flowspec_protocol(
            flowspec_rule.get_feature(FlowSpecRule.FeatureNames.protocol.value)
        )
        protocol_list = cls._validate_protocol_list(protocol_list)

        source_port_list = AccessListEntry._parse_conditional_fs_type(
            flowspec_rule.get_feature(FlowSpecRule.FeatureNames.source_port.value),
            default=[None]
        )

        destination_port_list = AccessListEntry._parse_conditional_fs_type(
            flowspec_rule.get_feature(FlowSpecRule.FeatureNames.destination_port.value),
            default=[None]
        )

        icmp_type = AccessListEntry._parse_icmp_value(
            flowspec_rule.get_feature(FlowSpecRule.FeatureNames.icmp_type.value),
            default=[None]
        )

        icmp_code = AccessListEntry._parse_icmp_value(
            flowspec_rule.get_feature(FlowSpecRule.FeatureNames.icmp_code.value),
            default=[None]
        )

        #  ACL doesn't support ranges of icmp types/codes, therefore skipping
        if len(icmp_type) > 1 or len(icmp_code) > 1:
            return []
        else:
            init_args['icmp_type'] = icmp_type[0]
            init_args['icmp_code'] = icmp_code[0]

        features_iter = product(protocol_list, source_port_list, destination_port_list)
        for proto, s_port, d_port in features_iter:
            # TODO: fix for ICMP (icmp codes incompatible with ports)
            init_args['protocol'] = proto
            init_args['source_port'] = s_port
            init_args['destination_port'] = d_port
            result_acl_rules.append(cls(**init_args))
        return result_acl_rules

    @staticmethod
    def _parse_flowspec_action(action):
        if FlowSpecRule.DENY_ACTION in action:
            return AccessListEntry.Command.deny.value

    @staticmethod
    def _parse_flowspec_address(fs_address):
        if not fs_address:
            return None

        prefix, mask = fs_address.split('/')
        if mask == '32':
            return 'host {}'.format(prefix)
        else:
            return fs_address

    @staticmethod
    def _parse_flowspec_protocol(fs_protocol):
        if not fs_protocol:
            return None

        fs_protocol_list = fs_protocol.split('|')
        acl_protocol_list = []
        for cond in fs_protocol_list:
            if '&' in cond:
                min_proto, max_proto = cond.split('&')
                min_proto = min_proto[2:]  # skipping '>='
                max_proto = max_proto[2:]  # skipping '<='
                for i in range(int(min_proto), int(max_proto) + 1):
                    acl_protocol_list.append(str(i))
            else:
                proto = cond[1:]  # skipping '='
                acl_protocol_list.append(proto)

        return acl_protocol_list

    @staticmethod
    def _parse_conditional_fs_type(fs_type_conditions, default=None):
        if not fs_type_conditions:
            return default

        conditions_list = fs_type_conditions.split('|')

        transformed_cond_list = []
        for cond in conditions_list:
            if '&' in cond:
                min_border, max_border = cond.split('&')
                min_border = min_border[2:]  # skipping '>='
                max_border = max_border[2:]  # skipping '<='
                transformed_cond_list.append('range {} {}'.format(min_border, max_border))
            else:
                cond = cond[1:]  # skipping '='
                transformed_cond_list.append('eq {}'.format(cond))

        if not transformed_cond_list:
            return default

        return transformed_cond_list

    @staticmethod
    def _parse_icmp_value(icmp_value, default=None):
        temp_values = AccessListEntry._parse_conditional_fs_type(icmp_value, default)
        if temp_values == default:
            return default

        res = []
        for val in temp_values:
            prefix, values = val.split(' ', 1)
            if prefix == 'eq':
                res.append(values)
            elif prefix == 'range':
                l_border, r_border = map(int, values.split(' '))
                res.extend(map(str, range(l_border, r_border)))
        return res

    @staticmethod
    def _validate_protocol(proto, raise_exception=True):
        if proto is None:
            if raise_exception:
                raise ValueError('Protocol is required. Allowed protocols: UDP, TCP, ICMP')
            return None

        proto = str(proto)
        if (proto not in ALLOWED_PROTOCOLS.values()) and (proto not in ALLOWED_PROTOCOLS.keys()):
            if raise_exception:
                raise ValueError('Passed wrong protocol value: {}'.format(proto))
            return None

        return proto

    @staticmethod
    def _validate_fragment_type(fragment_type, raise_exception=True):
        if not fragment_type:
            return None

        if fragment_type != 'is-fragment':
            if raise_exception:
                raise ValueError('Passed wrong fragment_type value: {}'.format(fragment_type))
            else:
                return None

        return fragment_type

    @classmethod
    def _parse_fs_fragment_type(cls, frag, default=None):
        if not frag:
            return default

        fragment_type_list = frag.split(':')

        for fragment_type in fragment_type_list:
            if 'IsF' in fragment_type:
                return 'is-fragment'

        return default


class AccessList:
    MIN_SEQUENCE_NUM = 1
    MAX_SEQUENCE_NUM = 2147483647

    def __init__(self, name, seq_step=10):
        if len(name) > 64:
            raise ValueError("Name {} is too long.".format(name))

        self._name = name
        self._seq_step = seq_step
        self._statements = SortedDict()
        self._fs_start = None
        self._fs_end = None

        self._changes = []

    @property
    def title(self):
        return 'ipv4 access-list {}'.format(self._name)

    @property
    def name(self):
        return self._name

    def _remove_statement(self, seq):
        statement = self._statements.pop(seq, None)
        if statement:
            self._changes.append('no {}'.format(seq))

    def apply_flowspec(self, flowspec, fs_start_seq=None):
        if flowspec.is_empty():
            return

        if self._fs_start:
            self.remove_flowspec()

        to_apply = [AccessListEntry.create_remark(FLOWSPEC_START_REMARK).rule]
        for fs_rule in flowspec.rules:
            access_list_entries = [ace.rule for ace in AccessListEntry.from_flowspec_rule(fs_rule)]
            to_apply.extend(access_list_entries)
        to_apply.append(AccessListEntry.create_remark(FLOWSPEC_END_REMARK).rule)

        if len(self._statements):
            last_seq, last_statement = self._statements.peekitem()
            next_free_seq = last_seq + self._seq_step
        else:
            last_statement = None
            next_free_seq = self._seq_step

        permit_all_statement = 'permit ipv4 any any'
        if last_statement == permit_all_statement:
            self._remove_statement(last_seq)
            next_free_seq = last_seq

        to_apply.append(permit_all_statement)

        if fs_start_seq is None or fs_start_seq < next_free_seq:
            fs_start_seq = next_free_seq

        after_apply_last_seq = fs_start_seq + len(to_apply)
        if after_apply_last_seq > self.MAX_SEQUENCE_NUM:
            raise IndexError(
                "Added sequence {} exceed maximum allowed {}".format(after_apply_last_seq,
                                                                     self.MAX_SEQUENCE_NUM)
            )

        cur_seq = fs_start_seq
        for statement in to_apply:
            self._add_statement(statement, cur_seq)
            cur_seq += 1

    def _add_statement(self, statement, seq=None, save_change=True):
        self._statements.update({seq: statement})
        if save_change:
            self._changes.append('{} {}'.format(seq, statement))

    def add_statement(self, statement, seq=None):
        statement_pat = re.compile(r'(deny|remark|permit) .+')
        if not statement_pat.match(statement):
            raise ValueError('Wrong statement format: {}'.format(statement))

        if seq is None:
            if self.is_empty():
                seq = self._seq_step
            else:
                seq = self._statements.peekitem()[0] + self._seq_step

        seq = int(seq)

        if seq > self.MAX_SEQUENCE_NUM:
            raise IndexError('Sequence index is out of range: {}. Max: {}'.format(seq, self.MAX_SEQUENCE_NUM))

        self._add_statement(statement, seq)

    def is_empty(self):
        return len(self._statements) == 0

    def is_flowspec_applied(self):
        return bool(self._fs_start)

    @classmethod
    def from_config(cls, raw_config_list):
        if len(raw_config_list) <= 1:
            raise ValueError('Passed empty config list.')

        acl_name_pat = re.compile(r'ipv4 access-list ([^\s]{1,64})')
        acls = []
        cur_acl = None
        for line in raw_config_list:
            acl_title = acl_name_pat.match(line)
            if acl_title:
                cur_acl = cls(acl_title.group(1))
            elif line == '!' and cur_acl is not None:
                acls.append(cur_acl)
                cur_acl = None
            elif cur_acl is not None:
                seq, statement = line.split(' ', 1)
                seq = int(seq)
                if FLOWSPEC_START_REMARK in statement and cur_acl._fs_start is None:
                    cur_acl._fs_start = seq
                elif FLOWSPEC_END_REMARK in statement:
                    cur_acl._fs_end = seq
                cur_acl._add_statement(statement, seq, save_change=False)
        return acls

    def remove_flowspec(self):
        if self._fs_start is None:
            return None

        fs_iter = self._statements.irange(minimum=self._fs_start, maximum=self._fs_end)
        for seq in list(fs_iter):
            self._remove_statement(seq)

        last_seq, last_statement = self._statements.peekitem()
        if last_seq > self._fs_start:
            self._remove_statement(last_seq)
            self._add_statement(last_statement, self._fs_start)

        self._fs_start = None
        self._fs_end = None

    def reset_changes(self):
        self._changes = []

    def get_changes_config(self):
        if not self._changes:
            return None
        changes_config = '\n'.join(self._changes)
        changes_config = '\n'.join([self.title, changes_config])
        return changes_config

    def get_config(self):
        if self.is_empty():
            return None
        config = '\n'.join(['{} {}'.format(seq, statement) for seq, statement in self._statements.iteritems()])
        config = '\n'.join([self.title, config])
        return config


class FlowSpecRule:
    class FeatureNames(Enum):
        source_ip = 'Source'
        destination_ip = 'Dest'
        protocol = 'Proto'
        destination_port = 'DPort'
        source_port = 'SPort'
        icmp_type = 'ICMPType'
        icmp_code = 'ICMPCode'

    DENY_ACTION = 'Traffic-rate: 0 bps'

    def __init__(self):
        self._raw_flow = None
        self._raw_actions = None
        self._flow_features = {}

    @staticmethod
    def _validate(raw_flow, raw_actions, raise_exception=True):
        if not raw_flow.strip().startswith("Flow"):
            if raise_exception:
                raise ValueError("Bad flow format: {}".format(raw_flow))
            return None, None

        if not raw_actions.strip().startswith("Actions"):
            if raise_exception:
                raise ValueError("Bad actions format: {}".format(raw_actions))
            return None, None

        raw_flow = raw_flow.split(':', 1)[1]
        raw_actions = raw_actions.split(':', 1)[1]

        raw_flow = raw_flow.split(',')
        feature_names = [f.value for f in FlowSpecRule.FeatureNames.__members__.values()]
        for feature in raw_flow:
            split_feature = feature.split(':', 1)
            if split_feature[0] not in feature_names:
                return None, None

        if not raw_actions.startswith(FlowSpecRule.DENY_ACTION):
            return None, None

        return raw_flow, raw_actions

    @property
    def actions(self):
        return self._raw_actions

    def get_feature(self, feature_name):
        if feature_name not in [f.value for f in FlowSpecRule.FeatureNames.__members__.values()]:
            raise ValueError("Wrong feature name: {}".format(feature_name))

        return self._flow_features.get(feature_name, None)

    @classmethod
    def from_config(cls, raw_flow, raw_actions):
        raw_flow, raw_actions = cls._validate(raw_flow, raw_actions)

        if not raw_flow or not raw_actions:
            return None

        flowspec = cls()
        flowspec._raw_flow = raw_flow
        flowspec._raw_actions = raw_actions
        for feature in raw_flow:
            split_feature = feature.split(':', 1)
            feature_name = split_feature[0]
            feature_value = split_feature[1]
            flowspec._flow_features.update({feature_name: feature_value})
        return flowspec


class FlowSpec:
    def __init__(self):
        self._raw_config = []
        self._rules = []

    @staticmethod
    def _validate_config(raw_config, raise_exception=True):
        if len(raw_config) <= 1:
            if raise_exception:
                raise ValueError("Empty flowspec: {}".format(raw_config))
            return None

        if raw_config[0].startswith("AFI:"):
            del raw_config[0]

        for i in range(0, len(raw_config), 2):
            if not (raw_config[i].strip().startswith("Flow") and raw_config[i + 1].strip().startswith("Actions")):
                if raise_exception:
                    raise ValueError("Bad flowspec format: {}".format(raw_config))
                return None
        return raw_config

    def is_empty(self):
        return not bool(len(self._rules))

    @property
    def config(self):
        return '\n'.join(self._raw_config)

    @property
    def md5(self):
        return hashlib.md5(self.config).hexdigest()

    @property
    def rules(self):
        return self._rules

    @classmethod
    def from_config(cls, fs_config):
        fs_config = cls._validate_config(fs_config, raise_exception=False)
        if fs_config is None:
            return None
        obj = cls()

        for i in range(0, len(fs_config), 2):
            rule = FlowSpecRule.from_config(raw_flow=fs_config[i], raw_actions=fs_config[i + 1])
            if rule:
                obj._rules.append(rule)
                obj._raw_config.append(fs_config[i])
                obj._raw_config.append(fs_config[i + 1])
        return obj


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


def get_acl_md5(access_lists):
    acl_raw_str = ''
    for acl in access_lists:
        acl_raw_str = '\n'.join([acl_raw_str, acl.rules()])
    return hashlib.md5(acl_raw_str).hexdigest()


def get_fs_md5(fs):
    if fs:
        return hashlib.md5('\n'.join(fs.raw_config)).hexdigest()


def get_interfaces_md5(interfaces):
    interfaces_conf = ''
    for interface, features in interfaces.iteritems():
        features_concat = '\n'.join(features)
        interface_conf = '\n'.join([interface, features_concat])
        interfaces_conf = '\n'.join([interfaces_conf, interface_conf])
    return hashlib.md5(interfaces_conf).hexdigest()


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
                for feature in feature_list:
                    f_match = pat.match(feature)
                    if f_match:
                        bound_acls.add(f_match.group(1))
                    else:
                        to_apply_default_acl.append(interface)

            if to_apply_default_acl:
                default_acl = [acl for acl in access_lists if acl.name == bgpfs2acl_tool.default_acl_name]
                if not default_acl:
                    access_lists.append(AccessList(bgpfs2acl_tool.default_acl_name))
                bound_acls.add(bgpfs2acl_tool.default_acl_name)

            for acl in access_lists:
                if acl.name in bound_acls:
                    acl.apply_flowspec(flowspec)
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
