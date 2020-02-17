import pprint
import tempfile


def write_config(cfg_entry, ztp_script):
    with tempfile.NamedTemporaryFile(delete=True) as f:
        f.write("%s" % cfg_entry)
        f.flush()
        f.seek(0)
        result = ztp_script.xrapply(f.name)
        f.close()
    return result['status']

def parse_range(port_string):

    print "* Parsing string: {0}".format(port_string)
    entry = []
    k = port_string.split('|')
    for i in range(0, len(k)):
        k[i] = k[i].lstrip()
        if '&' not in k[i]:

            entry.append(' eq ' + k[i].strip('='))
        else:
            min_range = k[i][k[i].find('>=')+2:k[i].find('&')]
            max_range = k[i][k[i].find('<=')+2:]
            entry.append(' range ' + min_range + ' ' + max_range)

    return entry


def interface_handler(int_dict):
    interface_chunks = []

    for s in int_dict:
        if 'interface' in s:
            interface_chunks.append([s])
        else:
            if s == '!':
                continue
            interface_chunks[len(interface_chunks)-1].append(s)
    # print interface_chunks

    for intf in interface_chunks:
        if ('interface Loop' in intf[0]) or ('interface Mgmt' in intf[0]):
            # print 'rm'
            interface_chunks.remove(intf)

        # acl_appliance = 'shutdown' not in intf and 'ipv4 a'

    pprint.pprint(interface_chunks)
    pass


interfaces_ztp = ['interface Loopback0',
                  'ipv4 address 1.1.1.1 255.255.255.255',
                  '! ----> X per node (1, 2, 3)',
                  'ipv6 address 1:1:1::1/128',
                  '!',
                  'interface Loopback100',
                  'vrf VRF_1',
                  'ipv4 address 100.1.1.1 255.255.255.255',
                  '!',
                  'interface Loopback200',
                  'vrf VRF_2',
                  'ipv4 address 200.1.1.1 255.255.255.255',
                  '!',
                  'interface MgmtEth0/RP0/CPU0/0',
                  'ipv4 address 10.30.111.171 255.255.255.0',
                  '!',
                  'interface TenGigE0/0/0/0',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/1',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/2',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/3',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/4',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/5',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/6',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/7',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/8',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/9',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/10',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/11',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/12',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/13',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/14',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/15',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/16',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/17',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/18',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/19',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/20',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/21',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/22',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/23',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/24',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/25',
                  'shutdown',
                  'ipv4 access-group test_acl_1 ingress',
                  '!',
                  'interface TenGigE0/0/0/26',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/27',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/28',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/29',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/30',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/31',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/32',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/33',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/34',
                  'shutdown',
                  'ipv4 access-group test_acl_2 egress',
                  '!',
                  'interface TenGigE0/0/0/35',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/36',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/37',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/38',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/39',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/40',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/41',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/42',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/43',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/44',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/45',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/46',
                  'shutdown',
                  '!',
                  'interface TenGigE0/0/0/47',
                  'shutdown',
                  '!',
                  'interface HundredGigE0/0/1/0',
                  'ipv4 address 16.16.16.30 255.255.255.0',
                  '!',
                  'interface HundredGigE0/0/1/1',
                  'cdp',
                  'ipv4 address 17.17.17.30 255.255.255.0',
                  'ipv6 address 11:1:2::1/64',
                  'load-interval 30',
                  '!',
                  'interface HundredGigE0/0/1/2',
                  'cdp',
                  'ipv4 address 18.18.18.30 255.255.255.0',
                  'ipv6 address 12:1:2::1/64',
                  'load-interval 30',
                  '!',
                  'interface HundredGigE0/0/1/3',
                  'cdp',
                  'ipv4 address 22.22.22.30 255.255.255.0',
                  'ipv6 address 11:1:3::1/64',
                  'load-interval 30',
                  '!',
                  'interface HundredGigE0/0/1/4',
                  'cdp',
                  'ipv4 address 27.27.27.30 255.255.255.0',
                  'ipv6 address 12:1:3::1/64',
                  'load-interval 30',
                  'ipv4 access-group test_acl_3 ingress',
                  '!',
                  'interface HundredGigE0/0/1/5',
                  'shutdown',
                  '!']

# interface_handler(interfaces_ztp)

