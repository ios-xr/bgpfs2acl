import pprint
import tempfile


def write_config(cfg_entry, ztp_script):
    with tempfile.NamedTemporaryFile(delete=True) as f:
        f.write("%s" % cfg_entry)
        f.flush()
        f.seek(0)
        result = ztp_script.xrapply(f.name)
        f.close()
    print 'Result {0}'.format(result)
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
    pprint.pprint(interface_chunks)
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

    pprint.pprint(interface_chunks)

    # Apply ACL
    print "Apply ACLs"
    pprint.pprint(int_apply_acl)
    # print "Don't apply ACL"
    # pprint.pprint(int_dont_touch)

    return {'apply_ACLs': int_apply_acl}
