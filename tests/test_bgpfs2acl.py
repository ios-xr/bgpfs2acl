import pytest

from src.flowspec import FlowSpec
from src.utils import convert_flowspec_to_acl_rules

DEFAULT_ACL_NAME = 'bgpfs2acl-test'

case1_input = '\n------------------------------ sh flowspec ipv4 -------------------------------\n\nAFI: IPv4\n  Flow           :Dest:7.7.7.7/32,Proto:=17,SPort:=19\n    Actions      :Traffic-rate: 0 bps  (policy.1.Example1.CHARGEN)\n\n'
case2_input = '\n------------------------------ sh flowspec ipv4 -------------------------------\n\nAFI: IPv4\n  Flow           :Dest:7.7.7.7/32,Proto:=17,DPort:=111\n    Actions      :Traffic-rate: 0 bps  (policy.1.Example2.SunRPC)\n\n'
case3_input = '\n------------------------------ sh flowspec ipv4 -------------------------------\n\nAFI: IPv4\n  Flow           :Dest:7.7.7.7/32,Source:80.2.1.0/24,Proto:=17,SPort:=19\n    Actions      :Traffic-rate: 0 bps  (policy.1.Example3.CHARGEN2)\n\n'
case4_input = '\n------------------------------ sh flowspec ipv4 -------------------------------\n\nAFI: IPv4\n  Flow           :Dest:7.7.7.7/32,Proto:=17,SPort:>=137&<=138\n    Actions      :Traffic-rate: 0 bps  (policy.1.Example4.NETBIOS)\n\n'
case5a_input = '\n------------------------------ sh flowspec ipv4 -------------------------------\n\nAFI: IPv4\n  Flow           :Dest:7.7.7.7/32,Proto:=17,SPort:=53,Length:>=768&<=65535\n    Actions      :Traffic-rate: 0 bps  (policy.1.Example5.DNS)\n\n'
case5b_input = '\n------------------------------ sh flowspec ipv4 -------------------------------\n\nAFI: IPv4\n  Flow           :Dest:7.7.7.7/32,Proto:=17,SPort:=53,Length:>=768&<=1600\n    Actions      :Traffic-rate: 0 bps  (policy.1.Example5.DNS)\n\n'
case_icmp_input = '\n------------------------------ sh flowspec ipv4 -------------------------------\n\nAFI: IPv4\n  Flow           :Dest:2.2.2.0/24,ICMPType:=2,ICMPCode:=2\n    Actions      :Traffic-rate: 0 bps  (policy.1.Example7.ICMP)\n\n'
case_frag_input = '\n------------------------------ sh flowspec ipv4 -------------------------------\n\nAFI: IPv4\n  Flow           :Dest:70.2.1.1/32,Frag:=IsF\n    Actions      :Traffic-rate: 0 bps  (policy.1.Example8a.FRAG1)\n  Flow           :Dest:70.2.1.2/32,Frag:=FF\n    Actions      :Traffic-rate: 0 bps  (policy.1.Example8b.FRAG2)\n  Flow           :Dest:70.2.1.3/32,Frag:=LF\n    Actions      :Traffic-rate: 0 bps  (policy.1.Example8c.FRAG3)\n\n'
case_redirect_ip_input = '\n------------------------------ sh flowspec ipv4 -------------------------------\n\nAFI: IPv4\n  Flow           :Dest:70.2.1.1/32\n    Actions      :Nexthop: 16.16.16.3  (policy.1.example9b.test9b)\n  Flow           :Dest:70.2.1.0/24\n    Actions      :Nexthop: 16.16.16.2  (policy.1.example9a.test9a)\n  Flow           :Dest:70.0.0.0/8\n    Actions      :Nexthop: 16.16.16.4  (policy.1.example9c.test9c)\n\n'
case_route_target_input = '\n------------------------------ sh flowspec ipv4 -------------------------------\n\nAFI: IPv4\n  Flow           :Dest:70.2.1.1/32\n    Actions      :Route-target: ASN2-1:10  (policy.1.exampleblue.testblue)\n  Flow           :Dest:70.0.0.0/8\n    Actions      :Route-target: ASN2-2:10  (policy.1.examplered.testred)\n\n'
case_redirect_vrf_input = '\n------------------------------ sh flowspec ipv4 -------------------------------\n\nAFI: IPv4\n  Flow           :Dest:70.2.1.1/32\n    Actions      :Redirect: VRF blue Route-target: ASN2-1:10  (policy.1.exampleblue.testblue)\n  Flow           :Dest:70.0.0.0/8\n    Actions      :Redirect: VRF red Route-target: ASN2-2:10  (policy.1.examplered.testred)\n\n'
@pytest.mark.parametrize(
    ('test_input', 'expected'),
    [
        (case1_input,
        ["deny 17 any eq 19 7.7.7.7/32"]),

        (case2_input,
        ["deny 17 any 7.7.7.7/32 eq 111"]),

        (case3_input,
        ["deny 17 80.2.1.0/24 eq 19 7.7.7.7/32"]),

        (case4_input,
        ["deny 17 any range 137 138 7.7.7.7/32"]),

        (case5a_input,
        []),
        (case_icmp_input,
        ["deny icmp any 2.2.2.0/24 2 2"]),

        (case_frag_input,
        ["deny ipv4 any 70.2.1.1/32 fragments",
        "deny ipv4 any 70.2.1.2/32 fragments",
        "deny ipv4 any 70.2.1.3/32 fragments"]),

        (case_redirect_ip_input,
        ["permit ipv4 any 70.2.1.1/32 nexthop1 ipv4 16.16.16.3",
        "permit ipv4 any 70.2.1.0/24 nexthop1 ipv4 16.16.16.2",
        "permit ipv4 any 70.0.0.0/8 nexthop1 ipv4 16.16.16.4"]),
        
        (case_route_target_input, []),

        (case_redirect_vrf_input,
        ["permit ipv4 any 70.2.1.1/32 nexthop1 vrf blue",
        "permit ipv4 any 70.0.0.0/8 nexthop1 vrf red"]),
        ]
)
def test_convert_flowspec(test_input, expected):
    flowspec = FlowSpec.from_config(test_input)
    result = convert_flowspec_to_acl_rules(flowspec)
    assert result == expected
