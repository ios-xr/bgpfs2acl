#!/usr/bin/env python
import argparse

import sys
import threading
from pprint import pprint
from func_lib import parse_range, write_config, interface_handler

sys.path.append("/pkg/bin/")

# noinspection PyUnresolvedReferences
from ztp_helper import ZtpHelpers

SYSLOG_SERVER = "11.11.11.2"
SYSLOG_PORT = 514
SYSLOG_LOCAL_FILE = "/root/ztp_python.log"


def parse_flowspec_rules_ipv4(rules):
    fs_dict = {}

    print '*' * 10
    k = 0

    for i in range(0, len(rules), 2):
        if 'Traffic-rate: 0 bps' in rules[i + 1]:
            fs_dict[k] = rules[i].split(',')
            fs_dict[k][0] = fs_dict[k][0][rules[i].split(',')[0].find(':') + 1:]
            k += 1
    pprint(fs_dict)

    return fs_dict


def constructed_acl(fs_rules):
    start_sequence = 10010
    alternator = 0

    # ICMP_code with ICMP_type migration
    for key, value in fs_rules.iteritems():
        buff = ''
        # buff1 = [s for s in value if 'ICMPCode' in s]
        # buff2 = [s for s in value if 'ICMPType' in s]
        # if len(buff1 + buff2) > 1:
        #     for el in buff1

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
            if 'Proto' in sub_part:
                ace_entry['Protocol'] = ' ' + sub_part[sub_part.find('=') + 1:]

            if 'Source' in sub_part:
                ace_entry['SourceIP'] = ' ' + sub_part[sub_part.find(':') + 1:]

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
                print ace
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

    # applied_config = ''.format(default_acl_name)
    applied_config = 'no ipv4 access-list {0}\nipv4 access-list {0} \n'.format(default_acl_name)

    for l in sorted(acl):
        # print l
        applied_config += '\n' + l

    applied_config += '\n'
    applied_config += '100999 permit any\n'
    # applied_config += """interface HundredGigE0/0/1/0
    #  ipv4 access-group bgp-fs2acl-ipv4 ingress
    #  !"""

    # with tempfile.NamedTemporaryFile(delete=True) as f:
    #
    #     f.write("%s" % applied_config)
    #     f.flush()
    #     f.seek(0)
    #     result = ztp_script.xrapply(f.name)
    #     print result['status']
    #     f.close()
    interaces_to_apply = get_interfaces()['apply_ACLs']

    for intf in interaces_to_apply:
        applied_config += intf + '\n'
        applied_config += 'ipv4 access-group {0} ingress \n'.format(default_acl_name)
    print applied_config
    write_config(applied_config, ztp_script)
    ztp_script.syslogger.info("Config was applied on the device")


def parse_interfaces(interfaces_with_acls):
    interfaces_with_acls += ""
    pass


def conv_initiate():
    threading.Timer(frequency, conv_initiate).start()
    flowspec_ipv4 = ztp_script.xrcmd({"exec_cmd": "sh flowspec ipv4"})
    interfaces_with_acls = ztp_script.xrcmd({"exec_cmd": "sh running interface | begin 'Hu'"})
    parse_interfaces(interfaces_with_acls['output'])
    if len(flowspec_ipv4) > 1:
        pprint(flowspec_ipv4['output'])
        print(" ")
        parsed_fs = parse_flowspec_rules_ipv4(flowspec_ipv4['output'][1:])
        constructed_acl(parsed_fs)


def get_interfaces():
    ztp_script.syslogger.info("Parsing Interfaces ")

    pprint(ztp_script.xrcmd({"exec_cmd": r"sh running interface | begin \"Gig|Ten|Twe|Fo|Hu\""}))
    return interface_handler(ztp_script.xrcmd({"exec_cmd": r"sh running interface | begin \"Gig|Ten|Twe|Fo|Hu\""})['output'])


def clean_script_actions():
    applied_config = """
    conf t
    no ipv4 access-list bgpfs2acl-ipv4
    commit
    !
    ztp terminate noprompt"""
    write_config(applied_config, ztp_script)
    ztp_script.syslogger.info("###### Script execution was complete ######")

    sys.exit('Terminating script')


if __name__ == "__main__":
    ztp_script = ZtpHelpers(syslog_file=SYSLOG_LOCAL_FILE, syslog_server=SYSLOG_SERVER, syslog_port=SYSLOG_PORT)
    ztp_script.syslogger.info("###### Starting BGPFS2ACL RUN on XR based device ######")

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
    # Todo add fix line numbers;
    # Todo add verbose story;

    args = parser.parse_args()
    if args.revert:
        clean_script_actions()

    frequency = int(args.frequency)
    default_acl_name = str(args.default_acl_name)
    # sys.exit()
    conv_initiate()
