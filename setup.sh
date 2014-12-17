#!/bin/sh

if [ "$EUID" != '0' ];
then
    echo "Need root"
    [[ $PS1 ]] && return || exit;
fi

# Use the pwntools binutils and install dependencies
apt-add-repository ppa:pwntools/binutils
apt-get update

for line in $(cat deps); do
apt-get install -y $line
done

# Install configuration
chown root:root  ./etc
chmod -R go-rwx  ./etc
cp -Rav ./etc/*   /etc/

# # Add pwnable user
# useradd pwntest

# # Kickstart svscan
# initctl start svscanboot
