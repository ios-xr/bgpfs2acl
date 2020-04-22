#!/usr/bin/env python
from __future__ import print_function

import argparse
import re

import sys
import threading
from pprint import pprint, pformat

import paramiko

from func_lib import parse_range, interface_handler, XRExecError, is_ipv4_subnet

import logging.config
import log_conf

logging.config.dictConfig(log_conf.LOG_CONFIG)
logger = logging.getLogger(__name__)


class XRCmdClient:
    def __init__(self, user, password='', host='127.0.0.1', port='57722'):

        self.ssh = paramiko.SSHClient()
        self.ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())

        look_for_keys, allow_agent = True, True

        if password:
            look_for_keys, allow_agent = False, False

        self.ssh.connect(
            host,
            username=user,
            password=password,
            port=int(port),
            look_for_keys=look_for_keys,
            allow_agent=allow_agent
        )
        channel = self.ssh.invoke_shell()
        self.stdin = channel.makefile('wb')
        self.stdout = channel.makefile('r')

        # this output was made for cleaning stdout out of info about established ssh connection
        ready_msg = 'connected succesfully'
        self.stdin.write('echo {}\n'.format(ready_msg))
        for line in self.stdout:
            if line.startswith(ready_msg):
                break

    def __del__(self):
        self.ssh.close()

    @staticmethod
    def _print_exec_out(cmd, out_buf):
        logger.info('command executed: {}'.format(cmd))
        if out_buf:
            logger.info('OUTPUT:')
            logger.info(pformat(out_buf))
            logger.info('end of OUTPUT')

    def _exec_xr_func(self, xr_func, xr_arg):
        """
        Execute xr command through the ssh using channel
        :param xr_func: xr function from ztp_helper.sh (xrcmd or xrapply_string)
        :param xr_arg: argument string being passed to an xr function
        :return:
        :raises: XRExecError due to failure
        """
        xr_arg = xr_arg.strip('\n')
        cmd = 'sudo su - root -c "source /pkg/bin/ztp_helper.sh && {func} \'{arg}\'"'.format(func=xr_func, arg=xr_arg)
        self.stdin.write(''.join([cmd, '\n']))
        finish = 'end of stdOUT buffer. finished with exit status'
        echo_cmd = 'echo {} $?'.format(finish)
        self.stdin.write(echo_cmd + '\n')
        self.stdin.flush()

        output = []
        exit_status = 0
        for line in self.stdout:
            if str(line).startswith(cmd) or str(line).startswith(echo_cmd):
                # up for now filled with shell junk from stdin
                output = []
            elif str(line).startswith(finish):
                # our finish command ends with the exit status
                exit_status = int(str(line).rsplit(None, 1)[1])
                break
            elif line.isspace():
                continue
            else:
                # get rid of 'coloring and formatting' special characters
                output.append(re.compile(r'(\x9B|\x1B\[)[0-?]*[ -/]*[@-~]').sub('', line).
                             replace('\b', '').replace('\r', ''))

        # first and last lines of output contain a prompt
        # join/split need because xr returns whitespace after 80th symbol
        if output and ''.join(echo_cmd.split()) in ''.join(output[-1].split()):
            output.pop()
        if output and ''.join(cmd.split()) in ''.join(output[0].split()):
            output.pop(0)

        # xrapply_string returns 1 due to failure, xrcmd returns 0, but has a pattern in first line
        if exit_status or (output and output[0].startswith('showtech_helper error:')):
            raise XRExecError(pformat(output))

        self._print_exec_out(cmd=cmd, out_buf=output)
        return output

    def xrcmd(self, arg_str):
        return self._exec_xr_func('xrcmd', arg_str)

    def xrapply_string(self, arg_str):
        return self._exec_xr_func('xrapply_string', arg_str)


def parse_flowspec_rules_ipv4(rules):
    fs_dict = {}

    print('*' * 10)
    k = 0

    for i in range(0, len(rules), 2):
        if 'Traffic-rate: 0 bps' in rules[i + 1]:
            fs_dict[k] = rules[i].split(',')
            fs_dict[k][0] = fs_dict[k][0][fs_dict[k][0].find(':') + 1:]
            k += 1
    pprint(fs_dict)

    return fs_dict


def constructed_acl(fs_rules, xr_client):
    start_sequence = 10010
    alternator = 0

    # ICMP_code with ICMP_type migration
    # TODO: explain this loop
    for key, value in fs_rules.iteritems():
        buff = ''

        # We expect to have bothL ICMP
        for val in value:
            if 'ICMPCode' in val or 'ICMPType' in val:
                if buff:
                    buff += '|' + val[val.find('='):]
                else:
                    buff += val[val.find('='):]

        if buff:
            value.append('ICMPMerged:' + buff)
        value = [i for i in value if not ('ICMPCode' in i or 'ICMPType' in i)]

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

    interfaces_to_apply = get_interfaces(xr_client)['apply_ACLs']

    for intf in interfaces_to_apply:
        applied_config += intf + '\n'
        applied_config += 'ipv4 access-group {0} ingress \n'.format(default_acl_name)
    logger.info(applied_config)
    xr_client.xrapply_string(applied_config)
    logger.info("Config was applied on the device")


def parse_interfaces(interfaces_with_acls):
    interfaces_with_acls += ""
    pass


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
    threading.Timer(frequency, conv_initiate, [xr_client]).start()
    flowspec_ipv4 = xr_client.xrcmd("sh flowspec ipv4")
    if len(flowspec_ipv4) > 1:
        parsed_fs = parse_flowspec_rules_ipv4(flowspec_ipv4[1:])
        constructed_acl(parsed_fs, xr_client)


def get_interfaces(xr_client):
    logger.info("Parsing Interfaces ")
    interfaces = xr_client.xrcmd("sh running interface")
    filtered_interfaces = filter_interfaces(interfaces, '^interface (Gig|Ten|Twe|Fo|Hu).*')
    logger.info(filtered_interfaces)
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
