from __future__ import unicode_literals

import re
import socket
from itertools import product

from enum import Enum
from sortedcontainers import SortedDict

from src.flowspec import FlowSpecRule

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

ALLOWED_PROTOCOLS = {
    'icmp': '1',
    'tcp': '6',
    'udp': '17',
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

        self._icmp_type = None
        if self._protocol in ('icmp', ALLOWED_PROTOCOLS['icmp']) and icmp_type is not None:
            if ((isinstance(icmp_type, int) or icmp_type.isdigit()) and not 0 <= int(icmp_type) <= 255) \
                    and icmp_type not in ICMP_TYPE_CODENAMES:
                raise ValueError('Wrong icmp_type value: {}'.format(icmp_type))
            self._icmp_type = icmp_type

        self._icmp_code = None
        if self._icmp_type and icmp_code is not None:
            if (isinstance(icmp_code, int) or icmp_code.isdigit()) and not 0 <= int(icmp_code) <= 255:
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

    def apply_flowspec(self, fs_ace_list, fs_start_seq=None):
        if not fs_ace_list:
            return

        self.remove_flowspec()

        to_apply = [AccessListEntry.create_remark(FLOWSPEC_START_REMARK).rule]
        to_apply.extend(fs_ace_list)
        to_apply.append(AccessListEntry.create_remark(FLOWSPEC_END_REMARK).rule)

        last_seq, last_statement = self._statements.peekitem()
        next_free_seq = last_seq + self._seq_step

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
