from pprint import pprint, pformat
import logging
logger = logging.getLogger(__name__)


def is_ipv4_subnet(ip_address):
    ip_address = ip_address.strip()
    ip_address = ip_address.split('/')
    if len(ip_address) != 2:
        return False
    net_address, net_mask = ip_address
    if not net_mask.isdigit() or int(net_mask) >= 32:
        return False

    net_mask = int(net_mask)
    net_addr_bin = ''.join([bin(int(x) + 256)[3:] for x in net_address.split('.')])
    suffix_len = 32 - net_mask

    if not net_addr_bin[net_mask:] == '0' * suffix_len:
        return False

    return True


def parse_range(port_string):
    print "* Parsing string: {0}".format(port_string)
    entry = []
    k = port_string.split('|')
    for i in range(0, len(k)):
        k[i] = k[i].lstrip()
        if '&' not in k[i]:

            entry.append(' eq ' + k[i].strip('='))
        else:
            min_range = k[i][k[i].find('>=') + 2:k[i].find('&')]
            max_range = k[i][k[i].find('<=') + 2:]
            entry.append(' range ' + min_range + ' ' + max_range)

    return entry


def interface_handler(int_dict):
    """
    This function responsible for dealing with interfaces and returning list of intf, to which ACL should be applied.

    :param int_dict: ZTP output for interface configurations
    :return: List of Interfaces where ACL should be applied.
    """
    # TODO add check where standard ACL alreaddy applied and withdraw it.
    interface_chunks = []
    int_apply_acl = []
    int_dont_touch = []

    for s in int_dict:
        if 'interface' in s:
            interface_chunks.append([s])
        else:
            if s == '!':
                continue
            interface_chunks[len(interface_chunks) - 1].append(s)

    for intf in interface_chunks:
        if ('interface Loop' in intf[0]) or ('interface Mgmt' in intf[0]):
            # print 'rm'
            interface_chunks.remove(intf)

        # acl_appliance = 'shutdown' not in intf and 'ipv4 a'
    for intf in interface_chunks:

        if ("Gig" or "Ten" or "Twe" or "For" or "Hun") not in intf[0]:
            continue

        if 'interface ' not in intf[0]:
            pass
        if 'shutdown' in intf:
            int_dont_touch.append(intf[0])
        else:
            if len(list(filter(lambda x: 'ipv4 access-group' in x, intf))) > 0:
                int_dont_touch.append(intf[0])
            else:
                int_apply_acl.append(intf[0])

    pprint(interface_chunks)

    # Apply ACL
    print "Apply ACLs"
    pprint(int_apply_acl)
    # print "Don't apply ACL"
    # pprint.pprint(int_dont_touch)

    return {'apply_ACLs': int_apply_acl}
