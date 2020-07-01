#!/usr/bin/env bash

### Starts bgpfs2acl script inside container
set -e

username=bgpfs2acl
script_name=${username}.py

ip netns exec global-vrf python $(pwd)/${script_name} --user=${username}