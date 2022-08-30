from __future__ import unicode_literals
import hashlib


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


def get_interfaces_md5(interfaces):
    interfaces_conf = ''
    for interface, features in interfaces.items():
        features_concat = '\n'.join(features)
        interface_conf = '\n'.join([interface, features_concat])
        interfaces_conf = '\n'.join([interfaces_conf, interface_conf])
    return hashlib.md5(interfaces_conf.encode('utf-8')).hexdigest()
