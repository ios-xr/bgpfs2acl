#!/usr/bin/env bash

### This script is made to prepare a host environment for bgpfs2acl script usage ###

set -e
username=bgpfs2acl

useradd \
    --system \
    --create-home \
    --user-group \
    --shell /bin/bash \
    --groups sudo \
    ${username}

mkdir -p /home/${username}/.ssh

ssh-keygen \
    -q \
    -t ed25519 \
    -C "${username}"\
    -N "" \
    -f "/home/${username}/${username}" \
    <<< y \
    > /dev/null

cat /home/${username}/${username}.pub | tee /home/${username}/.ssh/authorized_keys > /dev/null

chown ${username}:${username} /home/${username}/.ssh -R
chmod 700 /home/${username}/.ssh -R

echo "Finished successfully."
