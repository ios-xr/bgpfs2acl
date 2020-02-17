import unittest


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
