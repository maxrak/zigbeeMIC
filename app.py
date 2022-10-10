
# ZigBee frame encryption with AES-128-CCM*

#This notebook details how to encrypt ZigBee frames with AES-128-CCM*. Zigbee encryption is performed in three stages:
#* Input transformation (prepare data)
#* Encryption Transformation (returns encrypted frame)
#* Authentication Transformation (generate MIC)

#The frame used in this example is a frame listen on a real ZigBee network detailed on this page: [Autopsy of a ZigBee frame](https://lucidar.me/en/zigbee/autopsy-of-a-zigbee-frame/).
#The algorithm is detailed in the [section 4.3.1.1](https://lucidar.me/en/zigbee/files/docs-05-3474-21-0csg-zigbee-specification.pdf#page=404&zoom=100,93,0) and [annex A of the ZigBee specification](https://lucidar.me/en/zigbee/files/docs-05-3474-21-0csg-zigbee-specification.pdf#page=479&zoom=100,93,0).


# Python Cryptography Toolkit for AES encryption
from Crypto.Cipher import AES
from Crypto.Util import Counter
#Raw Data

key =   bytes([0xFB, 0x39, 0xCA, 0xAD, 0xD5, 0x0F, 0xEF, 0x91, 0x09, 0x49, 0xBA, 0xA8, 0x95, 0x04, 0xF5, 0xD9])
fullraw= '4802d36300001e7728ede625002377c6feff6f0d000099fa551ad18f6d7e3e4a56db62a8c5'
raw='6188377f11d36300004802d36300001e7728ede625002377c6feff6f0d000099fa551ad18f6d7e3e4a56db62a8c53eb5'
decpayload='400b060004010146011801'
mic = bytes([0xDB, 0x62, 0xA8, 0xC5])
L = 2
M = 4

gnonce=bytes([0xDB, 0x62, 0xA8, 0xC5])

# Print aray of bytes in hexadecimal
def printhex(x, sep = ' '):
  str = ''
  for b in x:  
    byte = hex(b)[2:]
    if (len(byte)<2)  :
      str += '0' + byte + sep
    else:
      str += hex(b)[2:] + sep 
  print (str[:-1].upper())


# 16 bits padding (with 0x00)
def pad(x):
  n=(16-len(x)%16)%16
  return x + bytes([0x00]*n)

def raw2list(raw):
  b=0;
  lst=[]
  tmp='0x'
  for letter in raw:
    tmp=tmp+letter
    if b == 0:
      b=1
    else:
      lst.append(bytes(tmp,'utf-8'))
      b=0
      tmp='0x'      
  return lst

def raw2bytes(raw):
  lst=[]
  for letter in raw:
    lst.append(bytes(int(letter)))

def decodepayload():
  decpayload='400b060004010146011801'
  mex=bytes.fromhex(decpayload)
  printhex(mex)
  return mex

def raw2NWKmsg(raw):
  mex=bytes.fromhex(raw)
  l=len(mex)
  msg={}
  msg["MACHeader"]=mex[0:9]
  msg["NwkHeader"]=mex[9:17]
  msg['NwkAuxiliaryHeader']=mex[17:31]
  msg['security_control']=msg['NwkAuxiliaryHeader'][0:1]
  msg['frame_counter']=msg['NwkAuxiliaryHeader'][1:5]
  msg['source_address']=msg['NwkAuxiliaryHeader'][5:13]
  msg['NwkPayload']=mex[31:l-6]
  msg['decNwkPayload']=decodepayload()
  msg['Key_sequence']=msg['NwkAuxiliaryHeader'][13:14]
  msg['APSHeader']=msg['decNwkPayload'][0:8]
  msg['APSPayload']=msg['decNwkPayload'][8:11]
  msg['MIC'] = mex[l-6:l-2]
  msg['MACFooter'] = mex[l-2:l]
  return msg


def EvaluateNonce(msg):
  nonce=msg['source_address']+msg['frame_counter']+msg['security_control']
  gnonce=nonce
  print ('nonce (',len(nonce), 'bytes):',end='')
  printhex(nonce)
  return nonce

def EvaluateA(msg):
  a = msg['NwkHeader'] + msg['NwkAuxiliaryHeader']
  print ('a (',len(a), 'bytes):',end='')
  printhex (a)
  return a;

def EvaluateM(msg):
  m = msg['APSHeader'] + msg['APSPayload']
# Octet string m
  print ('m (',len(m),'bytes): ',end='')
  printhex(m)
  return m

def EvaluateAuthData(a,m):
# Right-concatenate the octet string L(a) with the octet string a itself.
  AddAuthData = len(a).to_bytes(2, byteorder = 'big') + a
# Form the padded message AddAuthData
  AddAuthData = pad(AddAuthData)
  print('AddAuthData (',len(AddAuthData), 'bytes): ',end='')
  printhex(AddAuthData)
# Padding (with 0 up to a length multiple of 16)
  PlaintextData = pad(m)

  print ('PlaintextData (', len(PlaintextData), 'bytes): ',end='')
  printhex (PlaintextData)

  AuthData = AddAuthData + PlaintextData
  print ('AuthData (',len(AuthData), 'bytes): ',end='')
  printhex (AuthData)

  return AuthData

def EvaluateFlags():  
  #Da ricalcolare
  Flags = bytes([0x49]) # = ([0b01001001])
  print ('Flags (',len(Flags), 'bytes): ',end='')
  printhex (Flags)
  return Flags

def EvaluateB0(Flags,nonce,m):
  B0 = Flags + nonce + len(m).to_bytes(2, byteorder = 'big')
  print ('B0 Should be 16 bytes =>', len(B0), 'bytes :',end='')
  printhex (B0)
  return B0

def EvaluateX0():
  X0 = bytes([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])
  print ('X0 (',len(X0), 'bytes): ',end='')
  printhex(X0)
  return X0;

def EvaluateMIC(key,AuthData,X0,B0):
  cipher = AES.new(key, AES.MODE_CBC, X0)
  X1 = cipher.encrypt(B0 + AuthData)
  T = X1[-16:-12]
  print ('MIC = ',end='')
  printhex (T)
  return T

def byte_xor(ba1, ba2):
    return bytes([_a ^ _b for _a, _b in zip(ba1, ba2)])

def counter():
  return 

def EvaluateEncryptedMIC(T):
  Flags = bytes ([0b00000001])
  # printhex (Flags)

  A0 = Flags + gnonce + bytes([0x00, 0x00])
  A1 = Flags + gnonce + bytes([0x00, 0x01])

  ctr = Counter.new(128)
  cipher = AES.new(key, AES.MODE_CTR, nonce=gnonce)
  #Ciphertext = cipher.encrypt(m)
  #printhex (Ciphertext)
#  Encryption: S0:= E(Key, A0)
  S0 = cipher.encrypt(A0)
  print ('S0 (',len(S0),'bytes):',end='')
  printhex(S0[0:4])
  print ('T (',len(T),'bytes):',end='')
  printhex(T)
  eMIC=byte_xor(T,S0[0:4])
  print ('eMIC (',len(eMIC),'bytes):',end='')
  printhex(eMIC)
  

def printMsg(msg):
  print('Raw Packet:')

  print ('MACHeader (',len(msg['MACHeader']),'bytes):',end='')
  printhex (msg['MACHeader'])
  print ('NwkHeader (',len(msg['NwkHeader']),'bytes):',end='')
  printhex (msg['NwkHeader'])
  print ('NwkAuxiliaryHeader (',len(msg['NwkAuxiliaryHeader']),'bytes):',end='')
  printhex (msg['NwkAuxiliaryHeader'])
  print ('NwkPayload (',len(msg['NwkPayload']),'bytes):',end='')
  printhex(msg['NwkPayload'])
  
  print ('decNwkPayload (',len(msg['decNwkPayload']),'bytes):',end='')
  printhex(msg['decNwkPayload'])
  print ('security_control (',len(msg['security_control']),'bytes):',end='')
  printhex(msg['security_control'])
  print ('frame_counter (',len(msg['frame_counter']),'bytes):',end='')
  printhex(msg['frame_counter'])
  print ('source_address (',len(msg['source_address']),'bytes):',end='')
  printhex(msg['source_address'])
  print ('Key_sequence (',len(msg['Key_sequence']),'bytes):',end='')
  printhex(msg['Key_sequence'])
  
  print ('APSHeader (',len(msg['APSHeader']),'bytes):',end='')
  printhex(msg['APSHeader'])
  print ('APSPayload (',len(msg['APSPayload']),'bytes):',end='')
  printhex(msg['APSPayload'])
  
  print ('MIC (',len(msg['MIC']),'bytes):',end='')
  printhex(msg['MIC'])

  print ('MAC Footer (',len(msg['MACFooter']),'bytes):',end='')
  printhex(msg['MACFooter'])

  print('')

def counter():  
  Flags = bytes ([0b00000001])
  A1 = Flags + gnonce + bytes([0x00, 0x01])
  return A1

def _main():
  msg=raw2NWKmsg(raw)
  printMsg(msg)
  nonce = EvaluateNonce(msg)
  a = EvaluateA(msg)
  m = EvaluateM(msg)
  AuthData=EvaluateAuthData(a,m)
  Flags=EvaluateFlags()
  B0=EvaluateB0(Flags,nonce,m)
  X0=EvaluateX0()
  MIC=EvaluateMIC(key,AuthData,X0,B0)
  print('Orig MIC=',end='')
  printhex(msg['MIC'])
  eMIC=EvaluateEncryptedMIC(MIC)
  print('Done')

 


#  U = bytes(a ^ b for (a, b) in zip(S0[0:4], MIC))
#  printhex (U)

def _test():
  msg=raw2NWKmsg(raw)

  printMsg(msg)




_main()

#_test()