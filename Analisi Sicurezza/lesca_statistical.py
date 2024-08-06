import secrets
from Lesca import lesca_encrypt, initialization
from Lesca_8_bits import lesca_encrypt_8
from shared_session_key import shared_key_creation
import matplotlib.pyplot as plt

#VERSIONE A 64 BITS
secret = str(bin(secrets.randbits(512))[2:])
key = shared_key_creation()
msg = "0" * (10240*8)
V, perm1, perm2, perm3, perm4 = initialization(secret, key)
ran = lesca_encrypt(msg, V, perm1, perm2, perm3, perm4)
bucket_list = [0]*256
single_list = []
stop = int(len(ran)/8)
for i in range(0, stop):
    s = int(ran[i*8:(i+1)*8],2)
    single_list.append(s)
    bucket_list[s] = bucket_list[s]+1

#bar plot
lab = list(range(0,256))
plt.bar(lab, bucket_list,width = 0.8, color = ['green'])
plt.xlabel('Integer value')
plt.ylabel('Frequency')
plt.title('Statistical distribution of values per byte - 64 bits version')
plt.show()
#diffusion plot
li = list(range(0,len(single_list)))
plt.scatter(li,single_list, 0.001, 'c')
plt.xlabel('Number of Samples')
plt.ylabel('Integer Value of byte')
plt.title('Recurrence distribution of values per byte - 64 bits version')
plt.show()

#VERSIONE MISTA
#msg = "0"*(10240*8) #se si considera dim(ciphertext)==10240 bytes, bisogna modificare il valore di msg
V, perm1, perm2, perm3, perm4 = initialization(secret, key)
ran = lesca_encrypt_8(msg, V, perm1, perm2, perm3, perm4)
#s.write(ran + "\n")
bucket_list_2 = [0]*256
saidon_list = []
stop = int(len(ran)/8)
for i in range(0, stop):
    s = int(ran[i*8:(i+1)*8],2)
    saidon_list.append(s)
    bucket_list_2[s] = bucket_list_2[s]+1
plt.bar(lab, bucket_list_2,width = 0.8, color = ['green'])
plt.xlabel('Integer value')
plt.ylabel('Frequency')
plt.title('Statistical distribution of values per byte - 8 bits version')
plt.show()

le = list(range(0,len(saidon_list)))
plt.scatter(le,saidon_list, 1, 'c')
plt.xlabel('Number of Samples')
plt.ylabel('Integer Value of byte')
plt.title('Recurrence distribution of values per byte - 8 bits version')
plt.show()