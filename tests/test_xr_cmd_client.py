import io
import pprint
import unittest

import pytest

from bgpfs2acl import XRCmdClient

import logging

from func_lib import XRExecError

logging.disable(logging.WARNING)


class TestStringMethods(unittest.TestCase):

    def testcase1(self):
        # Example 1: DestIP/Protocol/Source-Port
        pass
        # Todo Add seven test cases


if __name__ == '__main__':
    fs_rules = {
        0: ['Dest:7.7.7.7/32', 'Source:80.2.1.0/24', 'Proto:=17', 'SPort:=19'],
        1: ['Dest:7.7.7.7/32', 'Proto:=17', 'DPort:=111'],
        2: ['Dest:7.7.7.7/32', 'Proto:=17', 'SPort:>=137&<=138'],
        3: ['Dest:7.7.7.7/32', 'Proto:=17', 'SPort:=19']}

    unittest.main()

# class-map type traffic match-all ex01
# match destination-address ipv4 7.7.7.7 255.255.255.255
# match protocol udp
# match source-port 19
# end-class-map

# deny  17 any eq 19 7.7.7.7/32


# class-map type traffic match-all ex02
# match destination-address ipv4 7.7.7.7 255.255.255.255
# match protocol udp
# match destination-port 111
# end-class-map

# deny  17 any 7.7.7.7/32 eq 111

# class-map type traffic match-all ex03
# match destination-address ipv4 7.7.7.7 255.255.255.255
# match source-address ipv4 80.2.1.0 255.255.255.0
# match protocol udp
# match source-port 19
# end-class-map

# deny  17 80.2.1.0/24 eq 19 7.7.7.7/32

# class-map type traffic match-all ex04
# match destination-address ipv4 7.7.7.7 255.255.255.255
# match protocol udp
# match source-port 137-138
# end-class-map

#

# class-map type traffic match-all ex05
# match destination-address ipv4 7.7.7.7 255.255.255.255
# match protocol udp
# match source-port 53
# match packet length 768-65535
# end-class-map
#
# class-map type traffic match-all ex06
# match destination-address ipv4 7.7.7.7 255.255.255.255
# match protocol udp
# match source-port 123
# match packet length 1-35 37-45 47-75 77-219 221-65535
# end-class-map
#
# class-map type traffic match-all ex07
# match destination-address ipv4 70.2.1.1 255.255.255.255
# match ipv4 icmp-type 3
# match ipv4 icmp-code 2
# end-class-map
#
# class-map type traffic match-all ex08
# match destination-address ipv4 70.2.1.1 255.255.255.255
# match fragment-type is-fragment
# end-class-map

IP_STUB = '1.1.1.1'
PORT_STUB = '55555'
USERNAME_STUB = 'test'
PASSWORD_STUB = 'test'


@pytest.fixture
def xr_client_fixture(mocker):
    def _xr_client_fixture(response_stream):
        class Channel:
            def __init__(self):
                pass

            def makefile(self, flag):
                return io.BytesIO(response_stream)

        mocker.patch('paramiko.SSHClient.connect')
        mocker.patch('paramiko.SSHClient.invoke_shell', return_value=Channel())
        return XRCmdClient(user=USERNAME_STUB, password=PASSWORD_STUB,host=IP_STUB, port=PORT_STUB)

    return _xr_client_fixture


class TestXRCmdClient:
    def test_xrcmd_success(self, xr_client_fixture):
        xr_client = xr_client_fixture("""Last login: Tue Mar 31 22:51:39 2020 from 1.2.3.4
Test 123
Testmachine:~$ echo connected succesfully
connected succesfully
Testmachine:~$ sudo su - root -c "source /pkg/bin/ztp_helper.sh && xrcmd \'sh flowspec ipv4\'"
echo end of stdOUT buffer. finished with exit status $?

AFI: IPv4
  Flow           test
    Actions      test test
  Flow           :Source:100.0.0.0/24
    Actions      :Traffic-rate: 0 bps  (bgp.1)
Testmachine:~$ echo end of stdOUT buffer. finished with exit status $?
end of stdOUT buffer. finished with exit status 0
""")
        result = xr_client.xrcmd("sh flowspec ipv4")
        assert result == [
            'AFI: IPv4\n',
            '  Flow           test\n',
            '    Actions      test test\n',
            '  Flow           :Source:100.0.0.0/24\n',
            '    Actions      :Traffic-rate: 0 bps  (bgp.1)\n'
        ]

    def test_xrapply_string_success(self, xr_client_fixture):
        xr_client = xr_client_fixture("""Last login: Tue Mar 31 22:51:39 2020 from 1.2.3.4
Test test test
Testmachine:~$ echo connected succesfully
connected succesfully
Testmachine:~$ sudo su - root -c "source /pkg/bin/ztp_helper.sh && xrapply_string \'no ipv4 access-list bgpfs2acl-ipv4
> ipv4 access-list bgpfs2acl-ipv4 
> 
> 10010 deny  17 any 7.7.7.7/32 eq 111
> 100999 permit any\'"
echo end of stdOUT buffer. finished with exit status $?
+ (Applying configuration) no ipv4 access-list bgpfs2acl-ipv4
+ (Applying configuration) ipv4 access-list bgpfs2acl-ipv4 
+ (Applying configuration) 
+ (Applying configuration) 10010 deny  17 any 7.7.7.7/32 eq 111
+ (Applying configuration) 100999 permit any
Testmachine:~$ echo end of stdOUT buffer. finished with exit status $?
end of stdOUT buffer. finished with exit status 0
""")
        result = xr_client.xrapply_string(
            """no ipv4 access-list bgpfs2acl-ipv4
ipv4 access-list bgpfs2acl-ipv4 
10010 deny  17 any 7.7.7.7/32 eq 111
100999 permit any\'"""
        )
        assert result == [
            u'+ (Applying configuration) no ipv4 access-list bgpfs2acl-ipv4\n',
            u'+ (Applying configuration) ipv4 access-list bgpfs2acl-ipv4 \n',
            u'+ (Applying configuration) \n',
            u'+ (Applying configuration) 10010 deny  17 any 7.7.7.7/32 eq 111\n',
            u'+ (Applying configuration) 100999 permit any\n'
        ]

    def test_xrcmd_fail(self, xr_client_fixture):
        xr_client = xr_client_fixture(
            """Last login: Tue Mar 31 22:51:39 2020 from 1.2.3.4
Test 123
Testmachine:~$ echo connected succesfully
connected succesfully
Testmachine:~$ sudo su - root -c "source /pkg/bin/ztp_helper.sh && xrcmd \'sh flowspec\'"
echo end of stdOUT buffer. finished with exit status $?
showtech_helper error: Parsing of command "sh flowspec " failed
sh flowspec
% Incomplete command.
Testmachine:~$ echo end of stdOUT buffer. finished with exit status $?
end of stdOUT buffer. finished with exit status 0
"""
        )
        with pytest.raises(XRExecError) as excinfo:
            xr_client.xrcmd('sh flowspec')

        assert str(excinfo.value) == pprint.pformat([
            'showtech_helper error: Parsing of command "sh flowspec " failed\n',
            'sh flowspec\n',
            '% Incomplete command.\n'
        ])

    def test_xrapply_string_fail(self, xr_client_fixture):
        xr_client = xr_client_fixture(
            """Last login: Tue Mar 31 22:51:39 2020 from 1.2.3.4
Test 123
Testmachine:~$ echo connected succesfully
connected succesfully
Testmachine:~$ sudo su - root -c "source /pkg/bin/ztp_helper.sh && xrapply_string \'no ipv4 access-list\'"
echo end of stdOUT buffer. finished with exit status $?
+ (Applying configuration) no ipv4 access-list
!! SYNTAX/AUTHORIZATION ERRORS: This configuration failed due to
!! one or more of the following reasons:
!!  - the entered commands do not exist,
!!  - the entered commands have errors in their syntax,
!!  - the software packages containing the commands are not active,
!!  - the current user is not a member of a task-group that has
!!    permissions to use the commands.

no ipv4 access-list
Testmachine:~$ echo end of stdOUT buffer. finished with exit status $?
end of stdOUT buffer. finished with exit status 1
"""
        )
        with pytest.raises(XRExecError) as excinfo:
            xr_client.xrapply_string('no ipv4 access-list')

        assert str(excinfo.value) == pprint.pformat([
            '+ (Applying configuration) no ipv4 access-list\n',
            '!! SYNTAX/AUTHORIZATION ERRORS: This configuration failed due to\n',
            '!! one or more of the following reasons:\n',
            '!!  - the entered commands do not exist,\n',
            '!!  - the entered commands have errors in their syntax,\n',
            '!!  - the software packages containing the commands are not active,\n',
            '!!  - the current user is not a member of a task-group that has\n',
            '!!    permissions to use the commands.\n',
            'no ipv4 access-list\n'
        ])
