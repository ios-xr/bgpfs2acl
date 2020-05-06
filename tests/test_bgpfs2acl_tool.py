from bgpfs2acl import BgpFs2AclTool


class TestBgpFs2AclTool:

    def test_get_interfaces_by_acl_name(self, mocker):
        interfaces_list = '''interface Loopback0
 ipv4 address 11.11.11.11 255.255.255.255
!
interface MgmtEth0/RP0/CPU0/0
 ipv4 address 10.30.111.177 255.255.255.224
 lldp
  enable
 !
!
interface TenGigE0/0/0/0
 shutdown
!
interface TenGigE0/0/0/1
 shutdown
 ipv4 access-group bgpfs2acl-ipv4 ingress
!
interface TenGigE0/0/0/2
 shutdown
 ipv4 access-group bgpfs2acl-ipv4 ingress
!
interface TenGigE0/0/0/3
 shutdown
 ipv4 access-group bgpfs2acl-ipv4 ingress
!
interface TenGigE0/0/0/4
 shutdown
 ipv4 access-group bgpfs2acl-ipv4 ingress
!
interface TenGigE0/0/0/5
 shutdown
 ipv4 access-group bgpfs2acl-ipv4 ingress
!'''.split('\n')
        acl_name = 'bgpfs2acl-ipv4'
        xr_client_mock = mocker.patch('xr_cmd_client.XRCmdClient')
        mocker.patch('bgpfs2acl.BgpFs2AclTool.get_interfaces', return_value=interfaces_list)
        tool = BgpFs2AclTool(xr_client_mock)
        result = tool.get_interfaces_by_acl_name(acl_name)

        assert result == '''interface TenGigE0/0/0/1
 shutdown
 ipv4 access-group bgpfs2acl-ipv4 ingress
interface TenGigE0/0/0/2
 shutdown
 ipv4 access-group bgpfs2acl-ipv4 ingress
interface TenGigE0/0/0/3
 shutdown
 ipv4 access-group bgpfs2acl-ipv4 ingress
interface TenGigE0/0/0/4
 shutdown
 ipv4 access-group bgpfs2acl-ipv4 ingress
interface TenGigE0/0/0/5
 shutdown
 ipv4 access-group bgpfs2acl-ipv4 ingress'''.split('\n')
