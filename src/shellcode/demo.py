from pwn import *
import traceback, unittest, time

class demo:
    def ptrsize(self):
        log.info('ptrsize()')
        self.send(p8(0))
        return u32(self.recvn(4))

    def write(self, where, bytes):
        log.info('write(%#x,%r)' % (where,bytes))
        self.send(p8(1))
        self.send(pack(where))
        self.send(p32(len(bytes)))
        self.send(bytes)

    def read(self, where, size):
        log.info('read(%#x,%r)' % (where,size))
        self.send(p8(2))
        self.send(pack(where))
        self.send(p32(size))
        return self.recvn(size)

    def overflow_stack(self, bytes):
        log.info('overflow_stack(%r)' % (bytes))
        self.send(p8(3))
        self.send(p32(len(bytes)))
        self.send(bytes)

    def overflow_string(self, bytes):
        log.info('overflow_string(%r)' % (bytes))
        self.send(p8(4))
        self.send(bytes + '\x00')

    def allocate(self, size):
        log.info('allocate(%r)' % (size))
        self.send(p8(5))
        self.send(p32(size))
        return unpack(self.recvn(context.bytes))

    def free(self, address):
        log.info('free(%#x)' % (address))
        self.send(p8(6))
        self.send(pack(address))

    def format(self, sz):
        log.info('format(%r)' % (sz))
        sz += '\x00'
        self.send(p8(7))
        self.send(p32(len(sz)))
        self.send(sz)
        return self.recvrepeat().rstrip('\x00')

    def leak_main(self):
        log.info('leak_main()')
        self.send(p8(8))
        return unpack(self.recvn(context.bytes))

    def leak_libc(self):
        log.info('leak_libc()')
        self.send(p8(9))
        return unpack(self.recvn(context.bytes))

    def shell(self, command):
        log.info('shell(%r)' % command)
        command += '\x00'
        self.send(p8(10))
        self.send(p32(len(command)))
        self.send(command)

    def segfault(self):
        log.info('segfault(%r)')
        self.send(p8(11))

    def exit(self):
        log.info('exit()')
        self.send(p8(12))
        assert self.recvall() == 'exit'

    def onebyte(self):
        log.info('onebyte()')
        self.send(p8(13))
        return self.recvn(1)

    def call(self, addr):
        log.info('call(%#x)' % addr)
        self.send(p8(14))
        self.send(pack(addr))

    def connect(self):
        log.info('connect()')
        self.send(p8(15))
        port = u16(self.recv(2))
        r = remote('localhost', port)
        assert r.recvn(4) == 'conn'
        return r

class demo_process(demo, process): pass
class demo_remote(demo, remote): pass

class Harness(object):
    def setUp(self):
        context.clear()
        context.arch = self.arch

    def test_basic_io(self):
        with demo_process(self.binary) as d:
            d.onebyte()

            assert d.ptrsize() == context.bytes

            data = 'A' * 0x10
            mem  = d.allocate(len(data))
            d.write(mem, data)
            assert data == d.read(mem, len(data))
            d.free(mem)

            assert 'hi'   == d.format('hi')

            d.shell('echo hi')
            assert 'hi\n' == d.recvrepeat()

    def test_exit_eof(self):
        # Ensure we get EOFError when read()ing
        with demo_process(self.binary) as d:
            d.exit()
            try:             d.recvn(1)
            except EOFError: pass
            else:            assert False, "Expected EOFError"

        # Ensure we get EOFError when write()ing
        with demo_process(self.binary) as d:
            d.exit()
            time.sleep(0.01)
            try:             d.send('ooga booga')
            except EOFError: pass
            else:            assert False, "Expected EOFError"

    def test_segfault_eof(self):
        # Ensure we get EOFError after segfault => write
        with demo_process(self.binary) as d:
            d.segfault()
            time.sleep(0.01)
            assert 'Got SIGSEGV' in d.recvall()
            try:             d.send('ooga booga')
            except EOFError: pass
            else:            assert False, "Expected EOFError"

    def test_libc(self):
        with demo_process(self.binary) as d:
            # Read the ELF header of LIBC to ensure bi-directional comms
            libc = d.leak_libc()
            assert '\x7FELF' == d.read(libc, 4)

    def test_dynelf(self):
        with demo_process(self.binary) as d:
            # Test ELF functionality
            elf    = ELF(self.binary)

            # Resolve 'system' manually and compare with DynELF
            d.shell('') # Cause got.system to be filled

            main        = d.leak_main()
            elf.address = main - (elf.symbols['main'] - elf.address)
            want        = unpack(d.read(elf.got['system'], context.bytes))

            @MemLeak
            def leak(addr, n=256):
                return d.read(addr, n)

            resolver = DynELF.from_elf(leak, elf)
            got      = resolver.lookup('system')
            assert got==want, "%#x == %#x" % (got, want)

    # def test_listen_spawn(self):
    #     l = listen()
    #     l.spawn_process(self.binary)
    #     r = demo_remote('localhost', l.lport)
    #     r.exit()

    def test_connect(self):
        with demo_process(self.binary) as d:
            d.connect()
            d.exit()

    def shellcode_tester(self, sc, d=None):
        d   = d or demo_process(self.binary)
        mem = d.allocate(len(sc))
        d.write(mem, sc)
        d.call(mem)
        return d

    def test_shellcode_ret(self):
        sc = asm(shellcraft.ret())
        d  = self.shellcode_tester(sc)
        d.exit()

    # def test_shellcode_findpeersh(self):
    #     with context.local(log_level= 'debug'):
    #         l = listen()
    #         l.spawn_process(self.binary)
    #         r = remote('localhost', l.lport)
    #         pid = pidof(r)
    #         # print "PID IS %r" % pid
    #         # gdb.attach(pid)
    #         # raw_input('waiting...')
    #         # sc = asm(shellcraft.findpeersh())
    #         # d = self.shellcode_tester(sc, r)
    #         # d.interactive()
    #     pass

class Testi386(unittest.TestCase, Harness):
    def __init__(self, *a, **kw):
        self.arch   = 'i386'
        self.binary = './shellcode-i386'
        super(Testi386, self).__init__(*a,**kw)


# if __name__ == '__main__':
#     contexts = [
#         {'arch': 'i386',    'endianness': 'little'},
#         {'arch': 'amd64',   'endianness': 'little'},
#         {'arch': 'arm',     'endianness': 'little'},
#         {'arch': 'aarch64', 'endianness': 'little'},
#         {'arch': 'powerpc', 'endianness': 'big'},
#         {'arch': 'thumb',   'endianness': 'little'}
#     ]

#     for ctx in contexts:
#         context.clear()
#         context(**ctx)
#         log.info(str(context))

#         binary = './shellcode-%s' % ctx['arch']


#         # Test shellcode functionality
#         sc = asm(shellcraft.sh())
#         d  = demo(binary)
#         mem = d.allocate(len(sc))
#         d.write(mem, sc)

#         gdb.attach(d, '''c''')
#         pause()

#         d.call(mem)
#         d.sendline('id')
#         d.interactive()


if __name__ == '__main__':
    with context.local(log_level = 'ERROR' if not args['DEBUG'] else 'DEBUG'):
        unittest.main()