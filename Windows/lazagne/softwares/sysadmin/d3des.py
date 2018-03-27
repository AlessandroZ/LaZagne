#!/usr/bin/env python
##
##  d3des.py - DES implementation
##
##  Copyright (c) 2009 by Yusuke Shinyama
##

# This is a Python rewrite of d3des.c by Richard Outerbridge.
#
# I referred to the original VNC viewer code for the changes that
# is necessary to maintain the exact behavior of the VNC protocol.
# Two constants and two functions were added to the original d3des
# code.  These added parts were written in Python and marked
# below.  I believe that the added parts do not make this program
# a "derivative work" of the VNC viewer (which is GPL'ed and
# written in C), but if there's any problem, let me know.
#
# Yusuke Shinyama (yusuke at cs dot nyu dot edu)


#  D3DES (V5.09) -
#  
#  A portable, public domain, version of the Data Encryption Standard.
#  
#  Written with Symantec's THINK (Lightspeed) C by Richard Outerbridge.
#  Thanks to: Dan Hoey for his excellent Initial and Inverse permutation
#  code;  Jim Gillogly & Phil Karn for the DES key schedule code; Dennis
#  Ferguson, Eric Young and Dana How for comparing notes; and Ray Lau,
#  for humouring me on.
#  
#  Copyright (c) 1988,1989,1990,1991,1992 by Richard Outerbridge.
#  (GEnie : OUTER; CIS : [71755,204]) Graven Imagery, 1992.
#  

from struct import pack, unpack


###################################################
###
###  start: changes made for VNC.
###

# This constant was taken from vncviewer/rfb/vncauth.c:
vnckey = [ 23,82,107,6,35,78,88,7 ]

# This is a departure from the original code.
#bytebit = [ 0200, 0100, 040, 020, 010, 04, 02, 01 ] # original
bytebit = [ 01, 02, 04, 010, 020, 040, 0100, 0200 ] # VNC version

# two password functions for VNC protocol.
def decrypt_passwd(data):
  dk = deskey(pack('8B', *vnckey), True)
  return desfunc(data, dk)

def generate_response(passwd, challange):
  ek = deskey((passwd+'\x00'*8)[:8], False)
  return desfunc(challange[:8], ek) + desfunc(challange[8:], ek)

###
###  end: changes made for VNC.
###
###################################################


bigbyte = [
  0x800000L,	0x400000L,	0x200000L,	0x100000L,
  0x80000L,	0x40000L,	0x20000L,	0x10000L,
  0x8000L,	0x4000L,	0x2000L,	0x1000L,
  0x800L, 	0x400L, 	0x200L, 	0x100L,
  0x80L,	0x40L,		0x20L,		0x10L,
  0x8L,		0x4L,		0x2L,		0x1L
  ]

# Use the key schedule specified in the Standard (ANSI X3.92-1981).

pc1 = [
  56, 48, 40, 32, 24, 16,  8,	 0, 57, 49, 41, 33, 25, 17,
   9,  1, 58, 50, 42, 34, 26,	18, 10,  2, 59, 51, 43, 35,
  62, 54, 46, 38, 30, 22, 14,	 6, 61, 53, 45, 37, 29, 21,
  13,  5, 60, 52, 44, 36, 28,	20, 12,  4, 27, 19, 11,  3
  ]

totrot = [ 1,2,4,6,8,10,12,14,15,17,19,21,23,25,27,28 ]

pc2 = [
  13, 16, 10, 23,  0,  4,  2, 27, 14,  5, 20,  9,
  22, 18, 11,  3, 25,  7, 15,  6, 26, 19, 12,  1,
  40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47,
  43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31
  ]

def deskey(key, decrypt):      # Thanks to James Gillogly & Phil Karn!
  key = unpack('8B', key)

  pc1m = [0]*56
  pcr = [0]*56
  kn = [0L]*32
  
  for j in range(56):
    l = pc1[j]
    m = l & 07
    if key[l >> 3] & bytebit[m]:
      pc1m[j] = 1
    else:
      pc1m[j] = 0
  
  for i in range(16):
    if decrypt:
      m = (15 - i) << 1
    else:
      m = i << 1
    n = m + 1
    kn[m] = kn[n] = 0L
    for j in range(28):
      l = j + totrot[i]
      if l < 28:
        pcr[j] = pc1m[l]
      else:
        pcr[j] = pc1m[l - 28]
    for j in range(28, 56):
      l = j + totrot[i]
      if l < 56:
        pcr[j] = pc1m[l]
      else:
        pcr[j] = pc1m[l - 28]
    for j in range(24):
      if pcr[pc2[j]]:
        kn[m] |= bigbyte[j]
      if pcr[pc2[j+24]]:
        kn[n] |= bigbyte[j]

  return cookey(kn)

def cookey(raw):
  key = []
  for i in range(0, 32, 2):
    (raw0, raw1) = (raw[i], raw[i+1])
    k  = (raw0 & 0x00fc0000L) << 6
    k |= (raw0 & 0x00000fc0L) << 10
    k |= (raw1 & 0x00fc0000L) >> 10
    k |= (raw1 & 0x00000fc0L) >> 6
    key.append(k)
    k  = (raw0 & 0x0003f000L) << 12
    k |= (raw0 & 0x0000003fL) << 16
    k |= (raw1 & 0x0003f000L) >> 4
    k |= (raw1 & 0x0000003fL)
    key.append(k)
  return key

SP1 = [
  0x01010400L, 0x00000000L, 0x00010000L, 0x01010404L,
  0x01010004L, 0x00010404L, 0x00000004L, 0x00010000L,
  0x00000400L, 0x01010400L, 0x01010404L, 0x00000400L,
  0x01000404L, 0x01010004L, 0x01000000L, 0x00000004L,
  0x00000404L, 0x01000400L, 0x01000400L, 0x00010400L,
  0x00010400L, 0x01010000L, 0x01010000L, 0x01000404L,
  0x00010004L, 0x01000004L, 0x01000004L, 0x00010004L,
  0x00000000L, 0x00000404L, 0x00010404L, 0x01000000L,
  0x00010000L, 0x01010404L, 0x00000004L, 0x01010000L,
  0x01010400L, 0x01000000L, 0x01000000L, 0x00000400L,
  0x01010004L, 0x00010000L, 0x00010400L, 0x01000004L,
  0x00000400L, 0x00000004L, 0x01000404L, 0x00010404L,
  0x01010404L, 0x00010004L, 0x01010000L, 0x01000404L,
  0x01000004L, 0x00000404L, 0x00010404L, 0x01010400L,
  0x00000404L, 0x01000400L, 0x01000400L, 0x00000000L,
  0x00010004L, 0x00010400L, 0x00000000L, 0x01010004L
  ]

SP2 = [
  0x80108020L, 0x80008000L, 0x00008000L, 0x00108020L,
  0x00100000L, 0x00000020L, 0x80100020L, 0x80008020L,
  0x80000020L, 0x80108020L, 0x80108000L, 0x80000000L,
  0x80008000L, 0x00100000L, 0x00000020L, 0x80100020L,
  0x00108000L, 0x00100020L, 0x80008020L, 0x00000000L,
  0x80000000L, 0x00008000L, 0x00108020L, 0x80100000L,
  0x00100020L, 0x80000020L, 0x00000000L, 0x00108000L,
  0x00008020L, 0x80108000L, 0x80100000L, 0x00008020L,
  0x00000000L, 0x00108020L, 0x80100020L, 0x00100000L,
  0x80008020L, 0x80100000L, 0x80108000L, 0x00008000L,
  0x80100000L, 0x80008000L, 0x00000020L, 0x80108020L,
  0x00108020L, 0x00000020L, 0x00008000L, 0x80000000L,
  0x00008020L, 0x80108000L, 0x00100000L, 0x80000020L,
  0x00100020L, 0x80008020L, 0x80000020L, 0x00100020L,
  0x00108000L, 0x00000000L, 0x80008000L, 0x00008020L,
  0x80000000L, 0x80100020L, 0x80108020L, 0x00108000L
  ]

SP3 = [
  0x00000208L, 0x08020200L, 0x00000000L, 0x08020008L,
  0x08000200L, 0x00000000L, 0x00020208L, 0x08000200L,
  0x00020008L, 0x08000008L, 0x08000008L, 0x00020000L,
  0x08020208L, 0x00020008L, 0x08020000L, 0x00000208L,
  0x08000000L, 0x00000008L, 0x08020200L, 0x00000200L,
  0x00020200L, 0x08020000L, 0x08020008L, 0x00020208L,
  0x08000208L, 0x00020200L, 0x00020000L, 0x08000208L,
  0x00000008L, 0x08020208L, 0x00000200L, 0x08000000L,
  0x08020200L, 0x08000000L, 0x00020008L, 0x00000208L,
  0x00020000L, 0x08020200L, 0x08000200L, 0x00000000L,
  0x00000200L, 0x00020008L, 0x08020208L, 0x08000200L,
  0x08000008L, 0x00000200L, 0x00000000L, 0x08020008L,
  0x08000208L, 0x00020000L, 0x08000000L, 0x08020208L,
  0x00000008L, 0x00020208L, 0x00020200L, 0x08000008L,
  0x08020000L, 0x08000208L, 0x00000208L, 0x08020000L,
  0x00020208L, 0x00000008L, 0x08020008L, 0x00020200L
  ]

SP4 = [
  0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
  0x00802080L, 0x00800081L, 0x00800001L, 0x00002001L,
  0x00000000L, 0x00802000L, 0x00802000L, 0x00802081L,
  0x00000081L, 0x00000000L, 0x00800080L, 0x00800001L,
  0x00000001L, 0x00002000L, 0x00800000L, 0x00802001L,
  0x00000080L, 0x00800000L, 0x00002001L, 0x00002080L,
  0x00800081L, 0x00000001L, 0x00002080L, 0x00800080L,
  0x00002000L, 0x00802080L, 0x00802081L, 0x00000081L,
  0x00800080L, 0x00800001L, 0x00802000L, 0x00802081L,
  0x00000081L, 0x00000000L, 0x00000000L, 0x00802000L,
  0x00002080L, 0x00800080L, 0x00800081L, 0x00000001L,
  0x00802001L, 0x00002081L, 0x00002081L, 0x00000080L,
  0x00802081L, 0x00000081L, 0x00000001L, 0x00002000L,
  0x00800001L, 0x00002001L, 0x00802080L, 0x00800081L,
  0x00002001L, 0x00002080L, 0x00800000L, 0x00802001L,
  0x00000080L, 0x00800000L, 0x00002000L, 0x00802080L
  ]

SP5 = [
  0x00000100L, 0x02080100L, 0x02080000L, 0x42000100L,
  0x00080000L, 0x00000100L, 0x40000000L, 0x02080000L,
  0x40080100L, 0x00080000L, 0x02000100L, 0x40080100L,
  0x42000100L, 0x42080000L, 0x00080100L, 0x40000000L,
  0x02000000L, 0x40080000L, 0x40080000L, 0x00000000L,
  0x40000100L, 0x42080100L, 0x42080100L, 0x02000100L,
  0x42080000L, 0x40000100L, 0x00000000L, 0x42000000L,
  0x02080100L, 0x02000000L, 0x42000000L, 0x00080100L,
  0x00080000L, 0x42000100L, 0x00000100L, 0x02000000L,
  0x40000000L, 0x02080000L, 0x42000100L, 0x40080100L,
  0x02000100L, 0x40000000L, 0x42080000L, 0x02080100L,
  0x40080100L, 0x00000100L, 0x02000000L, 0x42080000L,
  0x42080100L, 0x00080100L, 0x42000000L, 0x42080100L,
  0x02080000L, 0x00000000L, 0x40080000L, 0x42000000L,
  0x00080100L, 0x02000100L, 0x40000100L, 0x00080000L,
  0x00000000L, 0x40080000L, 0x02080100L, 0x40000100L
  ]

SP6 = [
  0x20000010L, 0x20400000L, 0x00004000L, 0x20404010L,
  0x20400000L, 0x00000010L, 0x20404010L, 0x00400000L,
  0x20004000L, 0x00404010L, 0x00400000L, 0x20000010L,
  0x00400010L, 0x20004000L, 0x20000000L, 0x00004010L,
  0x00000000L, 0x00400010L, 0x20004010L, 0x00004000L,
  0x00404000L, 0x20004010L, 0x00000010L, 0x20400010L,
  0x20400010L, 0x00000000L, 0x00404010L, 0x20404000L,
  0x00004010L, 0x00404000L, 0x20404000L, 0x20000000L,
  0x20004000L, 0x00000010L, 0x20400010L, 0x00404000L,
  0x20404010L, 0x00400000L, 0x00004010L, 0x20000010L,
  0x00400000L, 0x20004000L, 0x20000000L, 0x00004010L,
  0x20000010L, 0x20404010L, 0x00404000L, 0x20400000L,
  0x00404010L, 0x20404000L, 0x00000000L, 0x20400010L,
  0x00000010L, 0x00004000L, 0x20400000L, 0x00404010L,
  0x00004000L, 0x00400010L, 0x20004010L, 0x00000000L,
  0x20404000L, 0x20000000L, 0x00400010L, 0x20004010L
  ]

SP7 = [
  0x00200000L, 0x04200002L, 0x04000802L, 0x00000000L,
  0x00000800L, 0x04000802L, 0x00200802L, 0x04200800L,
  0x04200802L, 0x00200000L, 0x00000000L, 0x04000002L,
  0x00000002L, 0x04000000L, 0x04200002L, 0x00000802L,
  0x04000800L, 0x00200802L, 0x00200002L, 0x04000800L,
  0x04000002L, 0x04200000L, 0x04200800L, 0x00200002L,
  0x04200000L, 0x00000800L, 0x00000802L, 0x04200802L,
  0x00200800L, 0x00000002L, 0x04000000L, 0x00200800L,
  0x04000000L, 0x00200800L, 0x00200000L, 0x04000802L,
  0x04000802L, 0x04200002L, 0x04200002L, 0x00000002L,
  0x00200002L, 0x04000000L, 0x04000800L, 0x00200000L,
  0x04200800L, 0x00000802L, 0x00200802L, 0x04200800L,
  0x00000802L, 0x04000002L, 0x04200802L, 0x04200000L,
  0x00200800L, 0x00000000L, 0x00000002L, 0x04200802L,
  0x00000000L, 0x00200802L, 0x04200000L, 0x00000800L,
  0x04000002L, 0x04000800L, 0x00000800L, 0x00200002L
  ]

SP8 = [
  0x10001040L, 0x00001000L, 0x00040000L, 0x10041040L,
  0x10000000L, 0x10001040L, 0x00000040L, 0x10000000L,
  0x00040040L, 0x10040000L, 0x10041040L, 0x00041000L,
  0x10041000L, 0x00041040L, 0x00001000L, 0x00000040L,
  0x10040000L, 0x10000040L, 0x10001000L, 0x00001040L,
  0x00041000L, 0x00040040L, 0x10040040L, 0x10041000L,
  0x00001040L, 0x00000000L, 0x00000000L, 0x10040040L,
  0x10000040L, 0x10001000L, 0x00041040L, 0x00040000L,
  0x00041040L, 0x00040000L, 0x10041000L, 0x00001000L,
  0x00000040L, 0x10040040L, 0x00001000L, 0x00041040L,
  0x10001000L, 0x00000040L, 0x10000040L, 0x10040000L,
  0x10040040L, 0x10000000L, 0x00040000L, 0x10001040L,
  0x00000000L, 0x10041040L, 0x00040040L, 0x10000040L,
  0x10040000L, 0x10001000L, 0x10001040L, 0x00000000L,
  0x10041040L, 0x00041000L, 0x00041000L, 0x00001040L,
  0x00001040L, 0x00040040L, 0x10000000L, 0x10041000L
  ]

def desfunc(block, keys):
  (leftt, right) = unpack('>II', block)
  
  work = ((leftt >> 4) ^ right) & 0x0f0f0f0fL
  right ^= work
  leftt ^= (work << 4)
  work = ((leftt >> 16) ^ right) & 0x0000ffffL
  right ^= work
  leftt ^= (work << 16)
  work = ((right >> 2) ^ leftt) & 0x33333333L
  leftt ^= work
  right ^= (work << 2)
  work = ((right >> 8) ^ leftt) & 0x00ff00ffL
  leftt ^= work
  right ^= (work << 8)
  right = ((right << 1) | ((right >> 31) & 1L)) & 0xffffffffL
  work = (leftt ^ right) & 0xaaaaaaaaL
  leftt ^= work
  right ^= work
  leftt = ((leftt << 1) | ((leftt >> 31) & 1L)) & 0xffffffffL

  for i in range(0, 32, 4):
    work  = (right << 28) | (right >> 4)
    work ^= keys[i]
    fval  = SP7[ work		 & 0x3fL]
    fval |= SP5[(work >>  8) & 0x3fL]
    fval |= SP3[(work >> 16) & 0x3fL]
    fval |= SP1[(work >> 24) & 0x3fL]
    work  = right ^ keys[i+1]
    fval |= SP8[ work		 & 0x3fL]
    fval |= SP6[(work >>  8) & 0x3fL]
    fval |= SP4[(work >> 16) & 0x3fL]
    fval |= SP2[(work >> 24) & 0x3fL]
    leftt ^= fval
    work  = (leftt << 28) | (leftt >> 4)
    work ^= keys[i+2]
    fval  = SP7[ work		 & 0x3fL]
    fval |= SP5[(work >>  8) & 0x3fL]
    fval |= SP3[(work >> 16) & 0x3fL]
    fval |= SP1[(work >> 24) & 0x3fL]
    work  = leftt ^ keys[i+3]
    fval |= SP8[ work		 & 0x3fL]
    fval |= SP6[(work >>  8) & 0x3fL]
    fval |= SP4[(work >> 16) & 0x3fL]
    fval |= SP2[(work >> 24) & 0x3fL]
    right ^= fval

  right = (right << 31) | (right >> 1)
  work = (leftt ^ right) & 0xaaaaaaaaL
  leftt ^= work
  right ^= work
  leftt = (leftt << 31) | (leftt >> 1)
  work = ((leftt >> 8) ^ right) & 0x00ff00ffL
  right ^= work
  leftt ^= (work << 8)
  work = ((leftt >> 2) ^ right) & 0x33333333L
  right ^= work
  leftt ^= (work << 2)
  work = ((right >> 16) ^ leftt) & 0x0000ffffL
  leftt ^= work
  right ^= (work << 16)
  work = ((right >> 4) ^ leftt) & 0x0f0f0f0fL
  leftt ^= work
  right ^= (work << 4)

  leftt &= 0xffffffffL
  right &= 0xffffffffL
  return pack('>II', right, leftt)


# test
if __name__ == '__main__':
  key = '0123456789abcdef'.decode('hex')
  plain = '0123456789abcdef'.decode('hex')
  cipher = '6e09a37726dd560c'.decode('hex')
  ek = deskey(key, False)
  dk = deskey(key, True)
  assert desfunc(plain, ek) == cipher
  assert desfunc(desfunc(plain, ek), dk) == plain
  assert desfunc(desfunc(plain, dk), ek) == plain
  print 'test succeeded.'
