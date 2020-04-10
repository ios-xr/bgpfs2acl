#!/usr/bin/env bash

### Starts bgpfs2acl script inside container
set -e

script_name=bgpfs2acl.py
username=${script_name}

if [[ ! -x "${script_name}" ]]
then
    chmod +x ${script_name}
fi

ip netns exec global-vrf $(pwd)/bgpfs2acl.py --user=${username}