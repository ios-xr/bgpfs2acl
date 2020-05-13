#!/usr/bin/env python
from __future__ import print_function

import argparse
import re

import sys
import threading
from pprint import pprint

from func_lib import parse_range, interface_handler, is_ipv4_subnet

import logging.config
import log_conf
from xr_cmd_client import XRCmdClient

logging.config.dictConfig(log_conf.LOG_CONFIG)
logger = logging.getLogger(__name__)


class FlowSpecRule:
    def __init__(self, raw_flow, raw_actions):
        self.raw_flow, self.raw_actions = self._validate(raw_flow, raw_actions)

        for feature in self.raw_flow.split(','):
            if 'Dest' in feature:
                self._destination_ip = self._parse_destination(feature)
            if


    @staticmethod
    def _validate(raw_flow, raw_actions):
        if not raw_flow.strip().startswith("Flow"):
            raise ValueError("Bad flow format: {}".format(raw_flow))

        if not raw_actions.strip().startswith("Actions"):
            raise ValueError("Bad actions format: {}".format(raw_actions))

        return raw_flow, raw_actions

    @staticmethod
    def _parse_destination_ip(feature):
        return feature.rsplit()

    def _parse_proto(self):
        pass


class FlowSpec:
    def __init__(self, raw_config):

        self.raw_config = self._validate_config(raw_config)

    def _parse_config(self):
        self.rules = []
        for i in range(0, len(self.raw_config), 2):
            self.rules.append(FlowSpecRule(raw_flow=self.raw_config[i], raw_actions=self.raw_config[i+1]))


    @staticmethod
    def _validate_config(raw_config):
        if len(raw_config) <= 1:
            raise ValueError("Empty flowspec: {}".format(raw_config))

        if raw_config[0].startswith("AFI:"):
            raw_config = raw_config[1:]

        for i in range(0, len(raw_config), 2):
            if not (raw_config[i].strip().startswith("Flow") and raw_config[i+1].strip().startwith("Actions")):
                raise ValueError("Bad flowspec format: {}".format(raw_config))



class BgpFs2AclTool:
    def __init__(self, xr_client):
        self.xr_client = xr_client

    def get_interfaces(self, include_shutdown=True):
        """
        Returns XR interfaces dict, where a key is an 'interface ...' line, and a value is a list of applied
        features
        :param include_shutdown:
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

        return interfaces_dict

    def filter_interfaces(self, interfaces, regexp):
        """Filter the list of interfaces by matching the regular expression."""
        filtered_interfaces = {}
        pat = re.compile(r'{}'.format(regexp))

        for interface_name, feature_list in interfaces.iteritems():
            if pat.match(interface_name):
                filtered_interfaces.update({interface_name: feature_list})
        return filtered_interfaces

    def get_interfaces_by_acl_name(self, acl_name):
        result_dict = {}
        interfaces_dict = self.get_interfaces()
        for interface_name, feature_list in interfaces_dict.iteritems():
            for setting in feature_list:
                if ('access-group ' + acl_name + ' ingress') in setting:
                    result_dict.update({interface_name: feature_list})
                    break
        return result_dict

    def get_flowspec_rules(self):
        flowspec_ipv4 = self.xr_client.xrcmd('sh flowspec ipv4')

        for i in range(0, len(flowspec_ipv4), 2):
            flowspec_ipv4[i]

def parse_flowspec_rules_ipv4(rules):
    fs_dict = {}

    k = 0

    for i in range(0, len(rules), 2):
        if 'Traffic-rate: 0 bps' in rules[i + 1]:
            fs_dict[k] = rules[i].split(',')
            fs_dict[k][0] = fs_dict[k][0][fs_dict[k][0].find(':') + 1:]
            k += 1

    return fs_dict


def constructed_acl(fs_rules, xr_client):
    start_sequence = 10010
    alternator = 0

    acl, range_length, range_dport, range_sport, range_icmp = [], [], [], [], []

    # for i in range(len(fs_rules) - 1, -1, -1):
    for i in range(0, len(fs_rules)):
        ace_entry = {
            'Protocol': '',
            'SourceIP': ' any',
            'SourcePort': '',
            'DestIP': ' any',
            'DestPort': '',
            'fragment-type': '',
            'packet-length': '',
            'icmp': ''
        }
        for sub_part in fs_rules[i]:
            sub_part = sub_part.strip('\n')
            if 'Proto' in sub_part:
                ace_entry['Protocol'] = ' ' + sub_part[sub_part.find('=') + 1:]

            if 'Source' in sub_part:
                ace_entry['SourceIP'] = ' ' + sub_part[sub_part.find(':') + 1:]
                if is_ipv4_subnet(ace_entry['SourceIP']):
                    ace_entry['DestIP'] = ''
                    break

            if 'SPort' in sub_part:
                ace_entry['SourcePort'] = sub_part[sub_part.find(':') + 1:]

                if '|' in sub_part or '&' in sub_part:
                    range_sport = parse_range(sub_part[sub_part.find(':') + 1:])

                    ace_entry['SourcePort'] = range_sport[0]

                else:
                    ace_entry['SourcePort'] = ' eq ' + str(sub_part[sub_part.find(':') + 2:])

            if 'Dest' in sub_part:
                ace_entry['DestIP'] = ' ' + sub_part[sub_part.find(':') + 1:]

            if 'DPort' in sub_part:

                ace_entry['DestPort'] += ' eq ' + sub_part[sub_part.find(':') + 2:]
                if '|' in ace_entry['DestPort'] or '&' in ace_entry['DestPort']:
                    range_dport = parse_range(sub_part[sub_part.find(':') + 1:])
                    ace_entry['DestPort'] = range_dport[0]


                else:
                    ace_entry['DestPort'] = ' eq ' + str(sub_part[sub_part.find(':') + 2:])

            if 'Length' in sub_part:
                ace_entry['packet-length'] = ' ' + sub_part[sub_part.find(':') + 1:]
                if '|' in sub_part or '&' in sub_part:
                    range_length = parse_range(sub_part[sub_part.find(':') + 1:])
                    ace_entry['packet-length'] = range_length[0]

                else:
                    ace_entry['packet-length'] = ' eq ' + str(sub_part[sub_part.find(':') + 2:])

            if 'ICMP' in sub_part:
                ace_entry['Protocol'] = ' icmp '
                ace_entry['icmp'] = ' ' + sub_part[sub_part.find(':') + 1:]
                if '|' in sub_part or '&' in sub_part:
                    range_icmp = parse_range(sub_part[sub_part.find(':') + 1:])
                    ace_entry['icmp'] = ' ' + range_icmp[0].strip(' eq')

                else:
                    ace_entry['icmp'] = ' ' + str(sub_part[sub_part.find(':') + 2:]).strip('eq')

        ace = "{} deny ".format(start_sequence + i * 10 + alternator)
        ace += ace_entry['Protocol'] + \
               ace_entry['SourceIP'] + ace_entry['SourcePort'] + \
               ace_entry['DestIP'] + ace_entry['DestPort'] + ace_entry['packet-length'] + ace_entry['icmp']
        acl.append(ace)

        # for multiple ranges for packet
        if len(range_length) > 1:
            for n in range(1, len(range_length)):
                alternator += 10
                # print "i - {0}, alternator - {1}".format(i, alternator)

                ace = "{} deny ".format(start_sequence + i * 10 + alternator)
                ace += ace_entry['Protocol'] + \
                       ace_entry['SourceIP'] + ace_entry['SourcePort'] + \
                       ace_entry['DestIP'] + ace_entry['DestPort'] + range_length[n] + ace_entry['icmp']
                acl.append(ace)
            range_length = []

        # for multiple ranges for source port
        if len(range_sport) > 1:
            for n in range(1, len(range_sport)):
                alternator += 10

                ace = "{} deny ".format(start_sequence + i * 10 + alternator)
                ace += ace_entry['Protocol'] + \
                       ace_entry['SourceIP'] + range_sport[n] + \
                       ace_entry['DestIP'] + ace_entry['DestPort'] + \
                       ace_entry['packet-length'] + ace_entry['icmp']
                acl.append(ace)
            range_sport = []

        # for multiple ranges for dest port
        if len(range_dport) > 1:
            for n in range(1, len(range_dport)):
                alternator += 10

                ace = "{} deny ".format(start_sequence + i * 10 + alternator)
                ace += ace_entry['Protocol'] + \
                       ace_entry['SourceIP'] + ace_entry['SourcePort'] + \
                       ace_entry['DestIP'] + range_dport[n] + \
                       ace_entry['packet-length'] + ace_entry['icmp']
                print(ace)
                acl.append(ace)
            range_dport = []

        # # for multiple ranges for icmp
        if len(range_icmp) > 1:
            for n in range(1, len(range_icmp)):
                alternator += 10

                ace = "{} deny ".format(start_sequence + i * 10 + alternator)
                ace += ace_entry['Protocol'] + \
                       ace_entry['SourceIP'] + ace_entry['SourcePort'] + \
                       ace_entry['DestIP'] + ace_entry['DestPort'] + \
                       ace_entry['packet-length'] + ' ' + range_icmp[n].strip('eq =')
                acl.append(ace)
            range_icmp = []

    applied_config = 'no ipv4 access-list {0}\nipv4 access-list {0} \n'.format(default_acl_name)

    for l in sorted(acl):
        applied_config += '\n' + l

    applied_config += '\n'
    applied_config += '100999 permit any\n'
    interfaces = get_interfaces(xr_client)
    filtered_interfaces = filter_interfaces(interfaces, '^interface (Gig|Ten|Twe|Fo|Hu).*')

    interfaces_to_apply = get_interfaces(xr_client)['apply_ACLs']

    for intf in interfaces_to_apply:
        applied_config += intf + '\n'
        applied_config += 'ipv4 access-group {0} ingress \n'.format(default_acl_name)
    logger.info(applied_config)
    xr_client.xrapply_string(applied_config)
    logger.info("Config was applied on the device")


def filter_interfaces(interfaces, regexp):
    """Filter the list of interfaces by matching the regular expression."""

    filtered_interfaces = []
    pat = re.compile(r'{}'.format(regexp))

    for i, line in enumerate(interfaces):
        if pat.match(line):
            filtered_interfaces.append(line)
            j = i + 1
            while j < len(interfaces) and not interfaces[j].startswith('interface '):
                filtered_interfaces.append(interfaces[j])
                j += 1
    return filtered_interfaces


def conv_initiate(xr_client):
    # threading.Timer(frequency, conv_initiate, [xr_client]).start()
    flowspec_ipv4 = xr_client.xrcmd("sh flowspec ipv4")
    if len(flowspec_ipv4) > 1:
        parsed_fs = parse_flowspec_rules_ipv4(flowspec_ipv4[1:])
        constructed_acl(parsed_fs, xr_client)


def get_interfaces(xr_client):
    logger.info("Getting Interfaces")
    interfaces = xr_client.xrcmd("sh running interface")
    filtered_interfaces = filter_interfaces(interfaces, '^interface (Gig|Ten|Twe|Fo|Hu).*')
    return interface_handler(filtered_interfaces)


def clean_script_actions(ssh_client):
    logger.info('###### Reverting applied acl rules... ######')
    applied_config = "no ipv4 access-list bgpfs2acl-ipv4"
    ssh_client.xrapply_string(applied_config)
    logger.info("###### Script execution was complete ######")


if __name__ == "__main__":
    logger.info("###### Starting BGPFS2ACL RUN on XR based device ######")

    parser = argparse.ArgumentParser(description='BGP FlowSpec to ACL converter')
    parser.add_argument("-v", "--verbose", action="store_true",
                        help="increase output verbosity")
    parser.add_argument("-f", "--frequency", dest='frequency', default=30, type=int,
                        help="set script execution frequency, default value 30 sec")
    parser.add_argument("--line_start_number", help="Define the first line to add generated ACEs",
                        type=int, default=1200)
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

    args = parser.parse_args()

    xr_cmd_client = XRCmdClient(user=args.user, password=args.password, host=args.host, port=args.port)

    if args.revert:
        clean_script_actions(xr_cmd_client)
        sys.exit()

    frequency = int(args.frequency)
    default_acl_name = str(args.default_acl_name)
    conv_initiate(xr_cmd_client)
