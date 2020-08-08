
# APP overview 

BGPFS2ACL is a python script executed on XR 64b OS and aiming at converting the BGP flowspec rules present on the 
system into access-list entries.
Since all IOS XR routers support the PI part of the technology, they can behave as a FS client.
It will act as a “BGP FS Lite” implementation for systems not supporting BGP FS in hardware (ie: all non-J+/eTCAM 
based Fretta systems).


## Script Installation Process:

### Build image and save it to a devbox

This is one time operation to retrieve latest version of code. 

- Clone the repository to any machine (hereafter **devbox**) with **docker** & **git**:

    ```
    git clone https://github.com/ios-xr/bgpfs2acl.git
    ```

- Go to the directory:

    ```
    cd bgpfs2acl
    ```

- Build the image:

    ```
    docker build -t bgpfs2acl -f docker/Dockerfile-dev .
    ```

  **bgpfs2acl** is the name of built image

- save image to an archive for further delivery to a router:

    ```
     docker save bgpfs2acl > bgpfs2acl.tar
    ```

    Now our image ready! Next step to transfer it to the router(s) via scp/tftp/ftp based on your preferred/available technique. We will cover steps for SCP. 

### 1. Transfer and install the image to a router

- go to a linux shell on a router (need to be configured):

    ```
    ssh -p 57722 <username>@<router ip>
    ```

### On the router:

- transfer the repository and the image archive from **devbox** to the router:

    ```bash
    scp <username>@<devbox-ip>:<path-to-bgpfs2acl-repository> /misc/app_host/
    ```

- go to the repository

    ```bash
    cd /misc/app_host/bgpfs2acl
    ```

- load image from the archive to the docker environment:

```bash
      docker load < bgpfs2acl.tar
```

- check, that everything is ok and image was loaded successfully:

```bash
[ncs5501:~]$ docker images | grep bgpfs2acl
bgpfs2acl           latest              c9cc7b5ccff7        4 months ago        131.3 MB
```

### 2. Prepare linux environment

To make possible our tool and IOS XR interconnection, we need to make some steps: 

#### On the router: - in the same repository root directory:

```
  source prepare_host_environment.sh
```

- You should see something like:

    ```
    Checking if user already exist...
    Creating new user...
    Enter new UNIX password: 
    Retype new UNIX password: 
    passwd: password updated successfully
    New user created. Username: bgpfs2acl
    Keypair was created and stored in /home/bgpfs2acl
    Public key was added to ~/.ssh/authorized_keys.
    The key was copied to the shared location.
    ```

After that your router is ready to run the container

### 3. Set the parameters

### On the router:

Before the running, we need to set the parameters like execution frequency, default acl name, syslog parameters  and etc. Inside the repository root you can find a file called **parameters.env.example**. Here you can find all the configurable parameters of our programm. To configure the parameters, you need to follow these steps:

1. Copy the file **parameters.env.example** to **parameters.env** (or you can choose any other name but in that case, you will need to change the running script)

    ```bash
    cp parameters.env.example parameters.env
    ```

2. Open that file in any text editor. There you can find all the parameters an commentaries for them. Each parameter has been set to default value. You can change any value on your own if you need it. Here is the short description of all the parameters:

    ```bash
    #rules checking and updating interval in seconds
    FS2ACL_UPD_FREQUENCY=30

    #set this parameter to True if you need to remove all the rules applied by the script
    FS2ACL_REVERT=False 

    #default name of the ACL, which will be used for target interfaces without bounded ACL
    FS2ACL_DEFAULT_ACL_NAME=bgpfs2acl-ipv4 #

    #the sequence, starting from which all the generated rules will be applied to the targeted ACLs
    FS2ACL_FS_START_SEQ=100500

    #syslog ip address
    FS2ACL_SYSLOG_HOST=127.0.0.1

    #syslog port
    FS2ACL_SYSLOG_PORT=514

    #syslog file
    FS2ACL_SYSLOG_FILE=None

    #syslog level info
    FS2ACL_SYSLOG_LOGLEVEL=INFO

    #router host
    FS2ACL_ROUTER_HOST=127.0.0.1

    #router port
    FS2ACL_ROUTER_PORT=57722

    #linux user for connection to the router
    FS2ACL_ROUTER_USER=bgpfs2acl

    #user's password, not needed if using ssh key
    FS2ACL_ROUTER_PASSWORD=
    ```

3. In case if you changed the parameters filename you need to change it in the scripts/run_container.sh file. 

After all the parameters changes we are ready to start the programm

### 3. Run the container

### On the router:

- To run container execute the script from the repository:

    ```
    source run_container.sh
    ```

    Voila! Bgpfs2acl tool is up! Make some flowspec rules and check changes in access lists and interfaces.
    After that you can use usual **docker stop** and **docker run** to stop and run the container.



For default FlowSpec configurations samples please check the folder dev_configs. 
Macrocarpa acts as a FlowSpec client and Red_Pine announcing the FlowSpec rules.

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
 
 

