
# APP overview 

BGPFS2ACL is a python script executed on XR 64b OS and aiming at converting the BGP flowspec rules present on the 
system into access-list entries.
Since all IOS XR routers support the PI part of the technology, they can behave as a FS client.
It will act as a “BGP FS Lite” implementation for systems not supporting BGP FS in hardware (ie: all non-J+/eTCAM 
based Fretta systems).


## App Installation Process:

### 1. Build an RPM of the app

- Build a docker image image: ```docker build -t bgpfs2acl . ```
- Save the image: ```docker save b7f8277701ab > bgpfs2acl.tar.gz```
- Create the RPM following the instrucitons on: xr-appmgr-build (https://github.com/ios-xr/xr-appmgr-build) (the ```build.yaml``` needed is included in this repository)

### 2. Transfer and install the app to a router

- SCP the rpm to the router:
    
    ```
    scp bgpfs2acl-1.0.0-eXR_7.3.1.x86_64.rpm <router>:/misc/app_host
    ```

#### On the router:
- Install the app using appmanager
```
RP/0/RP0/CPU0:IOSXR2-R6#appmgr package install rpm /misc/app_host/bgpfs2acl-1.0.0-eXR_7.3.1.x86_64
```

- Check that the app was installed successfully:

```bash
RP/0/RP0/CPU0:IOSXR2-R6#sh appmgr packages installed                           
Package                                                     
------------------------------------------------------------    
bgpfs2acl-1.0.0-eXR_7.3.1.x86_64 
```

### 3. Open grpc port for communication with app

#### On the router:

```
grpc
 port 57777
 no-tls
!
```

After that your router is ready to run the app

### 4. Start the app

#### On the router:
In config mode
```
appmgr application bgpfs2acl activate type docker source bgpfs2acl docker-run-opts "-itd --network=host" docker-run-cmd "--router-host <host-ip-address> --router-port 57777 --router-user <username> --router-password <password> --syslog-filename /dev/stdout"
```

The first part: ```appmgr application bgpfs2acl activate type docker source bgpfs2acl docker-run-opts "-itd --network=host"``` specifies that ```bgpfs2acl``` is the app to be started. All of command line arguments are passed in ```docker-run-cmd``` in quotes.


Voila! Bgpfs2acl tool is up! Make some flowspec rules and check changes in access lists and interfaces.
After that you can use usual **docker stop** and **docker run** to stop and run the container.

You can always check that you container is running: 
    
 ```
RP/0/RP0/CPU0:IOSXR2-R6#show appmgr application name bgpfs2acl info summary 
Wed Aug 31 13:26:00.090 PDT
Application: bgpfs2acl
  Type: Docker
  Source: bgpfs2acl
  Config State: Activated
  Container ID: 0cc5f748fb3d90f9409f36a678f74cf69c590fe6de154a52b468008a08369843
  Image: bgpfs2acl:latest
  Command: "python3 -m bgpfs2acl --router-host 10.30.110.6 --router-port 57777 --router-user cisco --router-password cisco123 --syslog-loglevel DEBUG --syslog-filename /dev/stdout"
  Status: Up 43 seconds
  ```

To check the resource utilisation: 

```
RP/0/RP0/CPU0:IOSXR2-R6#show appmgr application name bgpfs2acl stats        
Wed Aug 31 13:26:13.871 PDT
Application Stats: bgpfs2acl
   CPU Percentage: 0.01%
   Memory Usage: 19.3MiB / 30.88GiB
   Memory Percentage: 0.06%
   Network IO: 0B / 0B
   Block IO: 0B / 0B
   PIDs: 0
```

The logs will be integrated and viewed with ```show logging```. For application specific logs, use ```show appmgr application name bgpfs2acl logs```

For default FlowSpec configurations samples please check the folder dev_configs. 
Macrocarpa acts as a FlowSpec client and Red_Pine announcing the FlowSpec rules.

## Script relies on iosxr-grpc-python

[Github for iosxr-grpc-python](https://github.com/cisco-ie/ios-xr-grpc-python)

The iosxr-grpc is a library with methods that are available to use over gRPC with IOS-XR boxes after 6.0.0. The API has several methods which allows a user to send simple RPC commands such as ```get``` and ```push``` using YANG and JSON.

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
 
 

