
# APP overview 

BGPFS2ACL is a python script executed on XR 64b OS and aiming at converting the BGP flowspec rules present on the 
system into access-list entries.
Since all IOS XR routers support the PI part of the technology, they can behave as a FS client.
It will act as a “BGP FS Lite” implementation for systems not supporting BGP FS in hardware (ie: all non-J+/eTCAM 
based Fretta systems).


## Script start:

The bare minimum to start the application, just execute the script with default parameters from XR Linux Shell. Git clone
is sufficient, no extra packages required. 

```
RP/0/RP0/CPU0:Macrocarpa# bash

[Macrocarpa:~]$ git clone https://github.com/Maikor/bgpfs2acl.git
Cloning into 'bgpfs2acl'...
remote: Enumerating objects: 30, done.
remote: Counting objects: 100% (30/30), done.
remote: Compressing objects: 100% (22/22), done.
remote: Total 40 (delta 15), reused 22 (delta 8), pack-reused 10
Unpacking objects: 100% (40/40), done.

[Macrocarpa:~]$ cd bgpfs2acl
Sat Feb 15 03:29:39.538 UTC
[Macrocarpa:~]$ python bgpfs2acl.py

```

For more parameters, check the help:

```
[Macrocarpa:~]$ python bgpfs2acl.py -h 

BGP FlowSpec to ACL converter

optional arguments:
  -h, --help            show this help message and exit
  -v, --verbose         increase output verbosity
  -f FREQUENCY, --frequency FREQUENCY
                        set script execution frequency, default value 30 sec
  --line_start LINE_START
                        Define the first line to add generated ACEs
  --revert REVERT       Start script in clean up mode
  --default-acl-name DEFAULT_ACL_NAME
                        Define default ACL name
```

To revert the script execution, please start the script with revert command. 


```
[Macrocarpa:~]$ python bgpfs2acl.py --revert

Building configuration...
Terminating script
[Macrocarpa:~]$
```

For default FlowSpec configurations sample please check the folder dev_configs. 
Macrocarpa acts as a FlowSpec client and Red_Pine announcing the FlowSpec rules.


Right now appliance for dynamic ACL (already existed on the devices) would live for a while in develop branch,
 would be merged after series of tests. Stay tuned for update. 

## Script relies on iosxr-ztp-python

[Github for iosxr-ztp-python](https://github.com/ios-xr/iosxr-ztp-python)

The ZtpHelpers class is implemented in ztp_helpers.py script.
 In this github repository you will find the library itself in the /lib directory.
  This library is available on the router by default starting IOS-XR 6.2.2. This file will
   exist at the location: /pkg/bin/ztp_helper.py on your router.

The python library is provided in the github repository to help a user easily understand 
the structure of the library and then inherit in the user side ztp script.

## Information retrieval 

To retrieve information call xrcmd used on a box.  
ACL with following name created on the device *ipv4 access-list bgpfs2acl-ipv4*  This is default name and could be 
changed with key "-n"


### Supported fields

- Protocol
- SourceIP
- SourcePort
- DestIP
- DestPort

More to be added;
Packet length first one. 


## BGP Flowspec Configuration example
 
```

flowspec
address-family ipv4
  service-policy type pbr TEST
!
 

policy-map type pbr TEST
class type traffic FRAG
  drop
!
class type traffic ICMP
  drop
!
class type traffic NETBIOS
  drop
!
class type traffic SNMP
  drop
!
class type traffic CHARGEN
  drop
!
class type traffic RIP
  drop
!
class type traffic MDNS
  drop
!
class type traffic MSSQL
  drop
!
class type traffic MEMCACHED
  drop
!
class type traffic SSDP
  drop
!
class type traffic SNMP
  drop
!
class type traffic NETBIOS
  drop
!
class type traffic ONCRPC
  drop
!
class type traffic NTP
  drop
!
class type traffic LDAP
  drop
!
class type traffic FRAG
  drop
!
class type traffic L2TP
  drop
!
class type traffic PAIR1
  drop
!
class type traffic PAIR2
  drop
!
class type traffic PAIR3
  drop
!
class type traffic
  drop
! 

!
class type traffic class-default
!
end-policy-map
!
 
class-map type traffic match-all ICMP
match destination-address ipv4 70.2.1.1 255.255.255.255
match source-address ipv4 80.2.1.0 255.255.255.0
match ipv4 icmp-type 3
match ipv4 icmp-code 2
end-class-map
!
class-map type traffic match-all FRAG
match destination-address ipv4 70.2.1.1 255.255.255.255
match source-address ipv4 80.2.1.1 255.255.255.255
match fragment-type is-fragment
end-class-map
!
class-map type traffic match-all NETBIOS
   match destination-address ipv4 7.7.7.7 255.255.255.255
   match protocol udp
   match source-port 137-138
!
class-map type traffic match-all SNMP
   match destination-address ipv4 7.7.7.7 255.255.255.255
   match protocol udp
   match source-port 161-162
!
class-map type traffic match-all CHARGEN
   match destination-address ipv4 7.7.7.7 255.255.255.255
   match protocol udp
   match source-port 19
!
class-map type traffic match-all DNS
   match destination-address ipv4 7.7.7.7 255.255.255.255
   match protocol udp
   match source-port 53
   match packet length 768-65535
!
class-map type traffic match-all ONCRPC
   match destination-address ipv4 7.7.7.7 255.255.255.255
   match protocol udp
   match source-port 111
!
class-map type traffic match-all NTP
   match destination-address ipv4 7.7.7.7 255.255.255.255
   match protocol udp
   match source-port 123
   match packet length 1-35 37-45 47-75 77-219 221-65535
!
class-map type traffic match-all LDAP
   match destination-address ipv4 7.7.7.7 255.255.255.255
   match protocol udp
   match source-port 389

```

​

## Conversion of BGP FS rules into ACL
​

### Example 1: DestIP/Protocol/Source-Port
​
<div class="highlighter-rouge">
<pre class="highlight">
<code>class-map type traffic match-all CHARGEN
   match destination-address ipv4 7.7.7.7 255.255.255.255
   match protocol udp
   match source-port 19</code>
</pre>
</div>
​
Will be translated in:
​
<div class="highlighter-rouge">
<pre class="highlight">
<code>ipv4 access-list TEST1
 100010 deny udp any eq 19 7.7.7.7 0.0.0.0
 100020 permit ipv4 any any
!</code>
</pre>
</div>
​
It will appear in the configuration as:  
​
```
ipv4 access-list TEST1
 100010 deny udp any eq 19 host 7.7.7.7
 100020 permit ipv4 any any
!
```

​
### Example 2: DestIP/Protocol/Dest-Port

```
class-map type traffic match-all SunRPC
   match destination-address ipv4 7.7.7.7 255.255.255.255
   match protocol udp
   match destination-port 111 
```
​
Will be translated in:
​
```
ipv4 access-list TEST2
 100010 deny udp any 7.7.7.7 0.0.0.0 eq 111
 100020 permit ipv4 any
!

```
​
It will be displayed in the config as:
​
<div class="highlighter-rouge">
<pre class="highlight">
<code>ipv4 access-list TEST2
 100010 deny udp any host 7.7.7.7 eq sunrpc
 100020 permit ipv4 any any
!</code>
</pre>
</div>


## Test cases

### Case 01: Basic creation of the ACL entries

Step 0  
- interface A configured with IPv4 address, no shut (up/up), no ACL applied
- interface B configured with IPv4 address, no shut (up/up), no ACL applied

Step 1
- Client receives BGP FS rule (take example in the "BGP Flowspec Rule example" section).  
- Client creates the ACL "Flowspec-ACL" and add ACEs for each match/action with the appropriate remark 
- Client applies ACL "Flowspec-ACL" ingress on the interfaces
- Client commits config

Step 2
- Verify consistency (show access / show run interface)
- Check syslog message is generated

Step 3
- Remove the rule from the controller  
- ACEs are removed but ACL "Flowspec-ACL" stays present on the interfaces A and B.

Step 4
- Verify ACL "Flowspec-ACL" still exists and is applied but empty (just permit any)


### Case 02: Ignore rules not supported by the script

Step 0  
- interface A configured with IPv4 address, no shut (up/up), no ACL applied
- interface B configured with IPv4 address, no shut (up/up), no ACL applied

Step 1
- Client receives 2x BGP FS rules: one with a drop action, one with a remark dscp action.  
- Client ignore rule with remark DSCP
- Client creates the ACL "Flowspec-ACL" and add ACEs for each match/action with the appropriate remark
- Client applies ACL "Flowspec-ACL" on the interfaces
- Client commits config

Step 2
- Verify consistency (show access / show run interface)
- Check syslog message is generated

Step 3
- Remove the rule from the controller  
- ACEs are removed but ACL "Flowspec-ACL" stays present on the interfaces A and B.

Step 4
- Verify ACL "Flowspec-ACL" still exists and is applied but empty (just permit any)



### Miscellaneous 
FlowSpec enabled on all L3 interfaces,  disable should be explicit. 
 
 

