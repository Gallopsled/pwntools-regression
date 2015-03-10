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
        return self.clean().rstrip('\x00')

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

    def get_system(self):
        log.info('get_system()')
        self.send(p8(18))
        return unpack(self.recvn(context.bytes))

#
# Note that there's a minor hack here to set the module to
# 'pwnlib' in order to ensure that we get the expected debugging output.
#
class demo_process(demo, process):  pass
class demo_remote(demo, remote):    pass

class Harness(object):
    def setUp(self):
        log_level = context.log_level
        context.clear()
        context.arch = self.arch
        context.log_level = log_level
        self.d = demo_process(self.binary)

    def tearDown(self):
        self.d.close()

    def test_basic_io(self):
        self.d.onebyte()

    def test_ptrsize(self):
        self.assertEqual(self.d.ptrsize(), context.bytes)

    def test_alloc_write_read_free(self):
        data = 'A' * 0x10
        mem  = self.d.allocate(len(data))
        self.d.write(mem, data)
        self.assertEqual(data, self.d.read(mem, len(data)))
        self.d.free(mem)

    def test_dprintf(self):
        self.assertEqual('hi', self.d.format('hi'))

    def test_shellecho(self):
        self.d.shell('echo hi')
        self.assertEqual('hi\n', self.d.recvn(3))


    def test_exit_eof_recv(self):
        # Ensure we get EOFError when read()ing
        self.d.exit()
        with self.assertRaises(EOFError):
            self.d.recvn(1)

    def test_exit_eof_send(self):
        # Ensure we get EOFError when write()ing
        self.d.exit()
        time.sleep(0.01)
        with self.assertRaises(EOFError):
            self.d.send('ooga booga')

    def test_segfault_eof(self):
        # Ensure we get EOFError after segfault => write
        self.d.segfault()
        time.sleep(0.01)
        self.assertIn('Got SIGSEGV', self.d.recvall())
        with self.assertRaises(EOFError):
            self.d.send('ooga booga')

    def test_libc(self):
        # Read the ELF header of LIBC to ensure bi-directional comms
        libc = self.d.leak_libc()
        self.assertEqual('\x7FELF', self.d.read(libc, 4))

    def test_dynelf(self):
        # Test ELF functionality
        elf    = ELF(self.binary)

        # Resolve 'system' manually and compare with DynELF
        self.test_shellecho()

        main        = self.d.leak_main()
        elf.address = main - (elf.symbols['main'] - elf.address)
        got_system  = elf.got['system']
        plt_system  = elf.plt['system']
        want        = unpack(self.d.read(got_system, context.bytes))

        log.info("plt.system %#x" % plt_system)

        self.assertNotEqual(want, plt_system)

        @MemLeak
        def leak(addr, n=16):
            return self.d.read(addr, n)

        real_system = self.d.get_system()
        log.info("real_system %#x" % real_system)

        # First, leak with just a pointer
        resolver = DynELF(leak, main)
        assert(real_system == resolver.lookup('system', 'libc'))

        # Second, leak with an elf
        resolver = DynELF(leak, elf=elf)
        assert(real_system == resolver.lookup('system', 'libc'))

    # def test_listen_spawn(self):
    #     l = listen()
    #     l.spawn_process(self.binary)
    #     r = demo_remote('localhost', l.lport)
    #     r.exit()

    def test_connect(self):
        self.d.connect()
        self.d.exit()

    def shellcode_tester(self, sc):
        mem = self.d.allocate(len(sc))
        self.d.write(mem, sc)
        self.d.call(mem)
        return self.d

    def test_shellcode_ret(self):
        sc = asm(shellcraft.ret())
        d  = self.shellcode_tester(sc)
        self.d.exit()

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

module = sys.modules[__name__]


def make_test(arch):
    for suffix in ('', 'partial', 'relro'):
        clazz = make_test2(arch, suffix)
        name  = arch 
        if suffix:
            name += '_'  + suffix
        clazz.__name__ = name 
        setattr(module, name, clazz)

def make_test2(arch, suffix):
    class C(Harness,unittest.TestCase):
        def __init__(self, *a, **kw):
            super(C, self).__init__(*a,**kw)
            self.arch   = arch
            self.binary = './%s-pwntest' % arch
            if suffix:
                self.binary += '-' + suffix
    return C

# make_test('i386')
# make_test('amd64')
make_test('arm')

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
#         self.d.write(mem, sc)

#         gdb.attach(d, '''c''')
#         pause()

#         self.d.call(mem)
#         self.d.sendline('id')
#         self.d.interactive()


if __name__ == '__main__':
    pwnlib.term.term_mode = False
    pwnlib.term.text.enabled = False
    #print sys.argv
    with context.local(log_level = 'ERROR' if '-v' not in sys.argv else 'DEBUG'):
        unittest.main()