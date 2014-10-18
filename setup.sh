#!/bin/sh

if [ "$EUID" != '0' ];
then
    echo "Need root"
    [[ $PS1 ]] && return || exit;
fi

# Automatic re-spawning of binaries
apt-get install daemontools xinetd

# Running foreign architecture binaries
apt-get install qemu-user-static

# Libraries required to run foreign-arch binaries
apt-get install libc6-arm64-cross libc6-armel-armhf-cross libc6-powerpc-cross libc6-x32 libc6-i386

# GCC variants required to build the test binary
apt-get install gcc-4.8-aarch64-linux-gnu gcc-4.8-arm-linux-gnueabihf gcc-4.8-powerpc-linux-gnu

# Install configuration
chown root:root  ./etc
chmod -R go-rwx  ./etc
cp -Rav ./etc/*   /etc/

# Add pwnable user
useradd pwntest

# Kickstart svscan
initctl start svscanboot
