#!/usr/bin/env bash

### This script is made to prepare a host environment for bgpfs2acl script usage ###

set -e
username=bgpfs2acl

id -u ${username} 2>&1 > /dev/null

if [[ $? -eq 1 ]]; then
    printf "Creating new user..."

    useradd \
        --system \
        --create-home \
        --user-group \
        --shell /bin/bash \
        --groups sudo \
        ${username}

     # generating random password for the newly created user
    head /dev/urandom | tr -dc A-Za-z0-9 | head -c 12 | xargs -I {} echo -e "{}\n{}" | passwd ${username} 2>&1 > /dev/null
    printf "New user created. Username: ${username}\n"
fi

mkdir -p /home/${username}/.ssh

ssh-keygen \
    -q \
    -t ed25519 \
    -C "${username}"\
    -N "" \
    -f "/home/${username}/${username}_key" \
    <<< y \
    > /dev/null

printf "Keypair was created and stored in /home/${username}\n"

cat /home/${username}/${username}_key.pub >> /home/${username}/.ssh/authorized_keys

chown ${username}:${username} /home/${username}/.ssh -R
chmod 700 /home/${username}/.ssh -R
chmod 600 /home/${username}/.ssh/authorized_keys

printf "Public key was added to ~/.ssh/authorized_keys.\n"

### TODO: need to figure out places permitted to mount to docker. Temporary solution:
cp /home/${username}/${username}_key /bindmnt_netns/
chmod 444 /bindmnt_netns/${username}_key
ln -s /bindmnt_netns/${username}_key /var/run/netns/${username}_key

printf "Symlink for key file was created.\n"