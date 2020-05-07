import pytest

from bgpfs2acl import BgpFs2AclTool


class TestBgpFs2AclTool:
    @pytest.mark.parametrize(
        ('test_input', 'expected'),
        [
            (  # Case 1: mixed
                    {
                        'interface Loopback0': [
                            'ipv4 address 11.11.11.11 255.255.255.255',
                        ],
                        'interface MgmtEth0/RP0/CPU0/0': [
                            'ipv4 address 10.30.111.177 255.255.255.224',
                            'lldp',
                            'enable',
                            'ipv4 access-group bgpfs2acl-ipv4 ingress',
                        ],
                        'interface TenGigE0/0/0/0': [
                            'shutdown',
                        ],
                        'interface TenGigE0/0/0/1': [
                            'ipv4 access-group bgpfs2acl-ipv4 ingress',
                        ],
                        'interface TenGigE0/0/0/2': [
                            'shutdown',
                        ],
                        'interface TenGigE0/0/0/3': [
                            'ipv4 access-group bgpfs2acl-ipv4 ingress',
                        ]
                    },
                    {
                        'interface MgmtEth0/RP0/CPU0/0': [
                            'ipv4 address 10.30.111.177 255.255.255.224',
                            'lldp',
                            'enable',
                            'ipv4 access-group bgpfs2acl-ipv4 ingress',
                        ],
                        'interface TenGigE0/0/0/1': [
                            'ipv4 access-group bgpfs2acl-ipv4 ingress',
                        ],
                        'interface TenGigE0/0/0/3': [
                            'ipv4 access-group bgpfs2acl-ipv4 ingress',
                        ]
                    }
            ),
            (  # Case 2: no acl
                    {
                        'interface Loopback0': [
                            'ipv4 address 11.11.11.11 255.255.255.255',
                        ],
                        'interface TenGigE0/0/0/0': [
                            'shutdown',
                        ],
                        'interface TenGigE0/0/0/2': [
                            'shutdown',
                        ],
                    },
                    {}
            ),
            (  # Case 3: only acl
                    {
                        'interface TenGigE0/0/0/1': [
                            'ipv4 access-group bgpfs2acl-ipv4 ingress',
                        ],
                    },
                    {
                        'interface TenGigE0/0/0/1': [
                            'ipv4 access-group bgpfs2acl-ipv4 ingress',
                        ],
                    }
            ),
            (  # Case 4: empty interface list
                    {},
                    {}
            )
        ]
    )
    def test_get_interfaces_by_acl_name(self, mocker, test_input, expected):
        interfaces_list = test_input
        acl_name = 'bgpfs2acl-ipv4'
        xr_client_mock = mocker.patch('xr_cmd_client.XRCmdClient')
        mocker.patch('bgpfs2acl.BgpFs2AclTool.get_interfaces', return_value=interfaces_list)
        tool = BgpFs2AclTool(xr_client_mock)
        result = tool.get_interfaces_by_acl_name(acl_name)

        assert result == expected
