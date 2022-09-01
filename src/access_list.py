from __future__ import unicode_literals

import logging
import re
import socket
from itertools import product
from enum import Enum
from sortedcontainers import SortedDict

from conf import settings
from src.flowspec import FlowSpecRule

logger = logging.getLogger(__name__)

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

ALLOWED_PROTOCOLS = {'icmp', '1', 'tcp', '6', 'udp', '17', 'ipv4'}

ALLOWED_ICMP_PROTO_VALUES = {'icmp', '1', 'ipv4'}

ICMP_PROTOCOL_VALUE = 'icmp'

IPV4_PROTOCOL_VALUE = 'ipv4'

ALLOWED_FS_KEYWORDS = {
    'Source',
    'Dest',
    'Proto',
    'DPort',
    'SPort',
    'ICMPType',
    'ICMPCode',
}

FLOWSPEC_START_REMARK = "FLOWSPEC RULES BEGIN. Do not add statements below this. Added automatically."
FLOWSPEC_END_REMARK = "FLOWSPEC RULES END"


class ACLValidationError(BaseException):
    pass


class AccessListEntry:
    MAX_PACKET_LENGTH = 16383

    class Command(Enum):
        deny = 'deny'
        permit = 'permit'
        remark = 'remark'

    def __init__(self, command, protocol=None, source_ip=None, source_port=None, destination_ip=None,
                 destination_port=None, icmp_type=None, icmp_code=None, packet_length=None, fragments=False,
                 nexthop_ip=None, nexthop_vrf=None, commentary=None):
        if command not in [c.value for c in AccessListEntry.Command.__members__.values()]:
            raise ACLValidationError('Passed wrong ACL command: {}'.format(command))
        self._command = command

        if command == AccessListEntry.Command.remark.value:
            if commentary is None:
                raise ACLValidationError("remark: no commentary provided.")
            self._commentary = commentary
            return

        self._protocol = self._validate_protocol(protocol)

        self._source_ip = self.validate_ip(source_ip)
        self._source_port = self.validate_rangeable_features(source_port)

        self._destination_ip = self.validate_ip(destination_ip)
        self._destination_port = self.validate_rangeable_features(destination_port)

        if (self._protocol in ALLOWED_ICMP_PROTO_VALUES or self._protocol == IPV4_PROTOCOL_VALUE) \
                and (self._source_port or self._destination_port):
            raise ACLValidationError(
                "Protocol {} can't be used with source or destination port.".format(self._protocol)
            )

        self._icmp_type, self._icmp_code = self._validate_icmp_values(icmp_type, icmp_code)

        self._packet_length = self._validate_packet_length(packet_length)

        self._fragments = self._validate_fragments(fragments)
        
        if nexthop_ip:
            self._nexthop = self._validate_nexthop_ip(nexthop_ip)

        # Special case for redirect to vrf
        elif nexthop_vrf:
            self._nexthop = self._validate_nexthop_vrf(nexthop_vrf)
        else:
            self._nexthop = None

    def _validate_nexthop_vrf(self, nexthop_vrf):
        if not nexthop_vrf:
            return None

        if self._command != AccessListEntry.Command.permit.value:
            raise ACLValidationError(
                "Wrong command: {}. Nexthop can be used only with permit acl command.".format(self._command))
        
        nexthop_vrf = 'nexthop1 vrf {}'.format(nexthop_vrf)
        return nexthop_vrf

    def _validate_nexthop_ip(self, nexthop_ip):
        if not nexthop_ip:
            return None

        if self._command != AccessListEntry.Command.permit.value:
            raise ACLValidationError(
                "Wrong command: {}. Nexthop can be used only with permit acl command.".format(self._command))
        try:
            socket.inet_aton(nexthop_ip)
        except socket.error:
            raise ACLValidationError('Wrong nexthop ip format: {}'.format(nexthop_ip))

        nexthop_ip = 'nexthop1 ipv4 {}'.format(nexthop_ip)
        return nexthop_ip

    def _generate_rule(self):
        if self._command == AccessListEntry.Command.remark.value:
            return ' '.join([self._command, self._commentary])

        features = [self._command, self._protocol, self._source_ip, self._source_port, self._destination_ip,
                    self._destination_port, self._icmp_type, self._icmp_code, self._packet_length, self._fragments,
                    self._nexthop]  # order is important

        features = [str(i) for i in features if i is not None]  # removed all empty fields

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
                raise ACLValidationError('Invalid ip format: {}'.format(features_list[0]))
            try:
                socket.inet_aton(ip_address[0])
            except socket.error:
                raise ACLValidationError('Invalid ip address passed: {}'.format(ip_address))
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
    def validate_rangeable_features(value):
        if not value:
            return None

        if value.startswith('range ') or value.startswith('eq '):
            to_check = value.split(' ')[1:]

            for num in to_check:
                if not num.isdigit() or not 0 < int(num) < 65536:
                    raise ACLValidationError('Passed invalid numerous value: {}'.format(value))

        return value

    def _validate_packet_length(self, packet_length):
        packet_length = self.validate_rangeable_features(packet_length)

        if not packet_length:
            return None

        packet_length_values = packet_length.split(' ')[1:]

        for value in packet_length_values:
            if int(value) > self.MAX_PACKET_LENGTH:
                raise ACLValidationError("Invalid packet-length: {}. Passed value {} is bigger than maximum permitted"
                                         " {}".format(packet_length, value, self.MAX_PACKET_LENGTH))

        packet_length = 'packet-length {}'.format(packet_length)

        return packet_length

    @staticmethod
    def validate_ip(ip):
        if ip is None:
            return 'any'

        if ip == 'any' or ip.startswith('host '):
            return ip

        ip_components = ip.split('/')

        if len(ip_components) != 2 or not (0 < int(ip_components[1]) < 33):
            raise ACLValidationError('Invalid ip parameter: {}'.format(ip))

        try:
            socket.inet_aton(ip_components[0])
        except socket.error:
            raise ACLValidationError('Invalid ip parameter: {}'.format(ip))

        return ip

    @staticmethod
    def _validate_protocol_list(protocols):
        if not protocols:
            return [IPV4_PROTOCOL_VALUE]

        validated = []
        for proto in protocols:
            proto = AccessListEntry._validate_protocol(proto)
            if proto:
                validated.append(proto)
        return validated

    def _validate_icmp_values(self, icmp_type, icmp_code):
        if not icmp_type:
            if icmp_code:
                raise ACLValidationError("ICMPcode can't be applied to ACE without ICMPtype")
            return None, None

        if not ((isinstance(icmp_type, int) or icmp_type.isdigit()) and 0 <= int(icmp_type) <= 255) \
                and icmp_type not in ICMP_TYPE_CODENAMES:
            raise ACLValidationError('Wrong icmp_type value: {}'.format(icmp_type))

        if self._protocol == IPV4_PROTOCOL_VALUE:
            self._protocol = ICMP_PROTOCOL_VALUE
        elif self._protocol not in ALLOWED_ICMP_PROTO_VALUES:
            raise ACLValidationError("icmp_type can't be used with {} protocol (allowed protocol values: {})"
                                     .format(self._protocol, ', '.join(ALLOWED_ICMP_PROTO_VALUES)))

        if icmp_code and not ((isinstance(icmp_code, int) or icmp_code.isdigit()) and 0 <= int(icmp_code) <= 255):
            raise ACLValidationError('Wrong icmp_code value: {}'.format(icmp_code))

        return icmp_type, icmp_code

    @classmethod
    def from_flowspec_rule(cls, flowspec_rule):
        result_acl_rules = []

        init_args = {}

        errors = {}

        protocol_list = [IPV4_PROTOCOL_VALUE]
        source_port_list = [None]
        destination_port_list = [None]
        packet_length_list = [None]

        for key, value in flowspec_rule.features_iter():
            try:
                if key == FlowSpecRule.FeatureNames.source_ip.value:
                    init_args['source_ip'] = value
                elif key == FlowSpecRule.FeatureNames.destination_ip.value:
                    init_args['destination_ip'] = value

                elif key == FlowSpecRule.FeatureNames.protocol.value:
                    protocol_list = AccessListEntry._parse_flowspec_protocol(value)
                    protocol_list = AccessListEntry._validate_protocol_list(protocol_list)

                elif key == FlowSpecRule.FeatureNames.source_port.value:
                    source_port_list = AccessListEntry._parse_conditional_fs_type(value, default=[None])

                elif key == FlowSpecRule.FeatureNames.destination_port.value:
                    destination_port_list = AccessListEntry._parse_conditional_fs_type(value, default=[None])

                elif key == FlowSpecRule.FeatureNames.packet_length.value:
                    packet_length_list = AccessListEntry._parse_packet_length(value, default=[None])

                elif key == FlowSpecRule.FeatureNames.icmp_type.value:
                    init_args['icmp_type'] = AccessListEntry._parse_icmp_value(value)

                elif key == FlowSpecRule.FeatureNames.icmp_code.value:
                    init_args['icmp_code'] = AccessListEntry._parse_icmp_value(value)

                elif key == FlowSpecRule.FeatureNames.fragment_type.value:
                    init_args['fragments'] = AccessListEntry._parse_fs_fragment_type(value)
                else:
                    errors.update({key: "Unsupported keyword"})
            except ACLValidationError as err:
                errors.update({key: str(err)})

        try:
            contains_vrf, command, nexthop = AccessListEntry._parse_flowspec_action(
                flowspec_rule.actions)
            init_args['command'] = command
            if contains_vrf:
                init_args['nexthop_vrf'] = nexthop
            else:
                init_args['nexthop_ip'] = nexthop
        except ACLValidationError as err:
            errors.update({'action': str(err)})

        if errors:
            errors = ';'.join(('{}: {}'.format(key, value) for key, value in errors.items()))
            logger.info("Failed to convert flow: {}. Errors: {}".format(flowspec_rule.flow, errors))
            return []

        features_iter = product(protocol_list, source_port_list, destination_port_list, packet_length_list)
        for proto, s_port, d_port, packet_length in features_iter:
            init_args['protocol'] = proto
            init_args['source_port'] = s_port
            init_args['destination_port'] = d_port
            init_args['packet_length'] = packet_length
            try:
                result_acl_rules.append(cls(**init_args))
            except ACLValidationError as err:
                logger.info("Failed to create ACL entry from FS rule: {}. {}".format(flowspec_rule.flow, str(err)))
        return result_acl_rules

    @staticmethod
    def _parse_flowspec_action(action):
        contains_vrf = False
        if action.startswith(FlowSpecRule.Actions.deny.value):
            return contains_vrf, AccessListEntry.Command.deny.value, None
        elif action.startswith(FlowSpecRule.Actions.nexthop.value):
            nexthop_ip = action.split(' ')[1]
            try:
                socket.inet_aton(nexthop_ip)
            except socket.error:
                raise ACLValidationError("Unsupported nexthop format: {}".format(nexthop_ip))
            return contains_vrf, AccessListEntry.Command.permit.value, nexthop_ip
        elif action.startswith(FlowSpecRule.Actions.redirect_vrf.value):
            contains_vrf = True
            return contains_vrf, AccessListEntry.Command.permit.value, action.split(' ')[2]
        raise ACLValidationError("Usupported action: {}".format(action))

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

        #  ACL doesn't support ranges of icmp types/codes, therefore skipping
        # TODO: change raising to error return
        if len(res) > 1:
            raise ACLValidationError("bgpfs2acl doesn't support icmp ranges: {}".format(icmp_value))

        return res[0]

    @staticmethod
    def _validate_protocol(proto):
        if proto is None:
            return IPV4_PROTOCOL_VALUE

        proto = str(proto)
        if proto not in ALLOWED_PROTOCOLS:
            raise ValueError('Passed unsupported protocol value: {}'.format(proto))

        return proto

    def _validate_fragments(self, fragments):
        if not fragments:
            return None

        if self._icmp_type or self._icmp_code:
            raise ACLValidationError("fragments keyword can't be used with icmp type/code")

        return 'fragments'

    @classmethod
    def _parse_fs_fragment_type(cls, frag):

        if frag:
            if 'IsF' in frag or 'FF' in frag or 'LF' in frag:
                return True
            else:
                raise ACLValidationError("Unsupported fragment type value: {}".format(frag))

        return False

    @classmethod
    def _parse_packet_length(cls, value, default):
        can_set_packet_length = getattr(settings, settings.PACKET_LENGTH_PERMISSION_NAME, None)
        if can_set_packet_length is None:
            raise ACLValidationError("{} flag wasn't set. Please, restart the program and "
                                     "check syslog for any xrcmd errors. Dropping rules with packet length."
                                     .format(settings.PACKET_LENGTH_PERMISSION_NAME))
        elif not can_set_packet_length:
            raise ACLValidationError("hw_module wasn't configured. Dropping rules with packet length.")

        else:
            return cls._parse_conditional_fs_type(value, default)


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
        self.remove_flowspec()

        if not fs_ace_list:
            return

        to_apply = [AccessListEntry.create_remark(FLOWSPEC_START_REMARK).rule]
        to_apply.extend(fs_ace_list)
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
        for line in raw_config_list.split('\n'):
            acl_title = acl_name_pat.match(line)
            if acl_title:
                cur_acl = cls(acl_title.group(1))
            elif line == '!' and cur_acl is not None:
                acls.append(cur_acl)
                cur_acl = None
            elif cur_acl is not None:
                seq, statement = line.strip().split(' ', 1)
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

        # TODO: change this logic: need to find and move only 'permit any any' statement,
        #  which is located after flowspec, if there is no such ace, then skip
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
