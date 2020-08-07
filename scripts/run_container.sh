#!/usr/bin/env bash
set +e

name=bgpfs2acl

docker stop ${name} 2>&1 > /dev/null

docker rm ${name} 2>&1 > /dev/null

docker run -itd --name ${name} \
    -v /var/run/netns/global-vrf:/var/run/netns/global-vrf \
    -v /misc/app_host/${name}_key:/root/.ssh/id_ed25519 \
    --cap-add=SYS_ADMIN ${name}
    --env-file ./parameters.env