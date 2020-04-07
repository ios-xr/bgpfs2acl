#!/usr/bin/env bash

chmod +x bgpfs2acl.py
ip netns exec global-vrf $(pwd)/bgpfs2acl.py