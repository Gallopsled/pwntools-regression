#!/bin/sh

if [ "$EUID" != '0' ];
then
    echo "Need root"
    [[ $PS1 ]] && return || exit;
fi

# Automatic re-spawning of binaries when running as a service
apt-get install daemontools xinetd

# Running foreign architecture binaries
apt-get install qemu-user-statict

# Assemble and disassemble foreign-arch
apt-get install binutils-aarch64-linux-gnu
apt-get install binutils-arm-linux-gnueabihf
apt-get install binutils-powerpc-linux-gnu
apt-get install binutils-multiarch

# Libraries required to run foreign-arch binaries
apt-get install libc6-{arm64,armel-armhf,powerpc,ppc64el}-cross libc6-{x32,i386,amd64}

# GCC variants required to build the test binary
apt-get install gcc-multilib
apt-get install gcc-4.8-base:i386 gcc-4.8-base:amd64
apt-get install gcc-4.8-aarch64-linux-gnu gcc-4.8-arm-linux-gnueabihf gcc-4.8-powerpc-linux-gnu

while read line < deps; do
apt-get install $line
done

# # Install configuration
# chown root:root  ./etc
# chmod -R go-rwx  ./etc
# cp -Rav ./etc/*   /etc/

# # Add pwnable user
# useradd pwntest

# # Kickstart svscan
# initctl start svscanboot
