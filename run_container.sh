#!/usr/bin/env bash

script_name = bgpfs2acl.py

if ![[ -x "$script_name" ]]
then
    chmod +x bgpfs2acl.py
fi

ip netns exec global-vrf $(pwd)/bgpfs2acl.py