from src.access_list import AccessListEntry


def convert_flowspec_to_acl_rules(flowspec):
    converted_rules = []
    for fs_rule in flowspec.rules:
        access_list_entries = [ace.rule for ace in AccessListEntry.from_flowspec_rule(fs_rule)]
        converted_rules.extend(access_list_entries)
    return converted_rules 