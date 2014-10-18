#!/usr/bin/env python2
from pwn import *
context(**{k.lower():v for k,v in args.items()})

def launch():
    return process('shellcode-%s' % context.arch)

t = launch()

class PwnlibProcessTest(process):
    def ptrsize(self):
        self.send('\x00')
        return u32(self.recvn(4))
    def write(self, where, bytes):
        self.send('\x01')
        self.send(pack(where))
        self.send(p32(len(bytes)))
        self.send(bytes)
    def read(self, where, size):
        self.send('\x02')
        self.send(pack(where))
        self.send(p32(size))
        return self.recvn(size)
    def overflow_string(self, bytes):
        self.send('\x03')
        self.send(p32(len(bytes)))
        self.send(bytes)
    def overflow_string(self, bytes):
        self.send('\x04')
        self.send(bytes)
    def allocate(self, size):
        self.send('\x05')
        self.send(p32(size))
        return unpack(self.recvn(context.ptr_size))
    def free(self, address):
        self.send('\x06')
        self.send(pack(address))
    def format(self, sz):
        sz += '\x00'
        self.send('\x07')
        self.send(p32(len(sz)))
        self.send(sz)
        return self.recvrepeat(0.5)
    def leak_main(self):
        self.send('\x08')
        return unpack(self.recvn(context.ptr_size))
    def leak_libc(self):
        self.send('\x09')
        return unpack(self.recvn(context.ptr_size))
    def exit(self):
        self.send('\x00')
        self.close()
