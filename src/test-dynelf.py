from pwn import *
import traceback, unittest, time


class demo:
    def ptrsize(self):
        log.debug('ptrsize()')
        self.send(p8(0))
        return u32(self.recvn(4))

    def write(self, where, bytes):
        log.debug('write(%#x,%r)' % (where,bytes))
        self.send(p8(1))
        self.send(pack(where))
        self.send(p32(len(bytes)))
        self.send(bytes)

    def read(self, where, size):
        log.debug('read(%#x,%r)' % (where,size))
        self.send(p8(2))
        self.send(pack(where))
        self.send(p32(size))
        return self.recvn(size)

    def overflow_stack(self, bytes):
        log.debug('overflow_stack(%r)' % (bytes))
        self.send(p8(3))
        self.send(p32(len(bytes)))
        self.send(bytes)

    def overflow_string(self, bytes):
        log.debug('overflow_string(%r)' % (bytes))
        self.send(p8(4))
        self.send(bytes + '\x00')

    def allocate(self, size):
        log.debug('allocate(%r)' % (size))
        self.send(p8(5))
        self.send(p32(size))
        return unpack(self.recvn(context.word_size/8))

    def free(self, address):
        log.debug('free(%#x)' % (address))
        self.send(p8(6))
        self.send(pack(address))

    def format(self, sz):
        log.debug('format(%r)' % (sz))
        sz += '\x00'
        self.send(p8(7))
        self.send(p32(len(sz)))
        self.send(sz)
        return self.recvrepeat().rstrip('\x00')

    def leak_main(self):
        log.debug('leak_main()')
        self.send(p8(8))
        return unpack(self.recvn(context.word_size/8))

    def leak_libc(self):
        log.debug('leak_libc()')
        self.send(p8(9))
        return unpack(self.recvn(context.word_size/8))

    def shell(self, command):
        log.debug('shell(%r)' % command)
        command += '\x00'
        self.send(p8(10))
        self.send(p32(len(command)))
        self.send(command)

    def segfault(self):
        log.debug('segfault(%r)')
        self.send(p8(11))

    def exit(self):
        log.debug('exit()')
        self.send(p8(12))
        assert self.recvall() == 'exit'

    def onebyte(self):
        log.debug('onebyte()')
        self.send(p8(13))
        return self.recvn(1)

    def call(self, addr):
        log.debug('call(%#x)' % addr)
        self.send(p8(14))
        self.send(pack(addr))

    def connect(self):
        log.debug('connect()')
        self.send(p8(15))
        port = u16(self.recvn(2))
        r = remote('localhost', port)
        assert r.recvn(4) == 'conn'
        return r

    def leak_base(self):
        log.info("leak_base()")
        self.send(p8(16))
        base = unpack(self.recvn(context.word_size/8))
        log.indented("== %#x" % base)
        return base

    def leak_linkmap(self):
        log.info("leak_linkmap()")
        self.send(p8(17))
        result = unpack(self.recvn(context.word_size/8))
        log.indented("== %#x" % result)
        return result


    def leak_system(self):
        log.info("leak_system()")
        self.send(p8(18))
        result = unpack(self.recvn(context.word_size/8))
        log.indented("== %#x" % result)
        return result

class demo_process(demo, process): pass
class demo_remote(demo, remote): pass

# context.log_level = 'debug'

def test_binary(binary):
    print binary
    p = demo_process('./%s' % binary)
    # g = gdb.attach(p, 'continue\n')

    assert p.ptrsize() == context.word_size/8

    @MemLeak
    def leak(address):
        data = p.read(address, 4)
        log.debug("%#x => %s" % (address, (data or '').encode('hex')))
        return data

    system = p.leak_system()

    d = DynELF(leak, p.leak_main(), elf=binary)
    assert d.lookup(None,     'libc') == p.leak_libc()
    assert d.lookup('system', 'libc') == system

    libc = DynELF(leak, system)
    assert libc.lookup('system')      == system

def test(arch, mode):
    with context.local(arch=arch):
        binary = "%s%s%s" % (context.arch,'-pwntest',mode)
        test_binary(binary)

test('i386', '')
test('i386', '-partial')
test('i386', '-relro')
test('amd64', '')
test('amd64', '-partial')
test('amd64', '-relro')