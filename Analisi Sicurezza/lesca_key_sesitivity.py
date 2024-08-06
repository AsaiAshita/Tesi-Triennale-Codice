import secrets
from Lesca import RC4_KSA, xorshift64, block_creation, round_func
from Lesca_8_bits import trim, NUMBER_OF_WORDS, WORD_PRECISION, H
from shared_session_key import shared_key_creation
import numpy as np
import hashlib
import random
import matplotlib.pyplot as plt


_xormap = {('0', '1'): '1', ('1', '0'): '1', ('1', '1'): '0', ('0', '0'): '0'}
def xor(x, y):
    "Funzione che effettua la XOR tra due stringhe usando una map."
    return ''.join([_xormap[a, b] for a, b in zip(x, y)])

def lesca_encrypt(msg, d):
    "Versione modificata di lesca_encrypt, prende in input l'hashed secret session key ed il messaggio, non gestisce interamente l'inizializzazione (così da poter poi modificare il bit dellaSecret Session Key, cosa impossibile da fare se si usa il codice principale) e poi esegue normalmente."
    #Divisione dell'output della hash function in 4 parti da 96 bit ed in 1 da 128 bit per la seguente generazione delle tabelle di permutazione e del vettore Key Stream
    k1= d[0:96]
    k2= d[96:192]
    k3= d[192:288]
    k4= d[288:384]
    k5= d[384:512]

    #genero le tabelle di permutazione
    perm1=RC4_KSA(k1,12)
    perm2=RC4_KSA(k2,12)
    perm3=RC4_KSA(k3,12)
    perm4=RC4_KSA(k4,12)

    V = []
    V.append(xorshift64(np.uint64(int(k5[0:64],2))))
    V.append(xorshift64(np.uint64(int(k5[64:128],2))))
    for i in range (2,NUMBER_OF_WORDS):
        V.insert(i, xorshift64(V[i-2]))
    
    #trasformo il messaggio in una stringa in binario
    msg = ''.join(format(x, 'b').zfill(WORD_PRECISION) for x in bytearray(msg, 'utf-8'))

    #calcolo il numero di blocchi che andrò a formare
    nb=(len(msg))/H
    if type(nb)==float: 
        nb = int(nb+1)
    #creo i blocchi
    b = block_creation(msg,H,nb)
    #applico LESCA
    res = round_func(b, V, perm1, perm2, perm3, perm4, nb)
    #ritorno il messaggio criptato
    return ''.join(res)

def lesca_encrypt_8(msg, d):
    "Versione modificata di lesca_encrypt, prende in input l'hashed secret session key ed il messaggio, non gestisce interamente l'inizializzazione (così da poter poi modificare il bit dellaSecret Session Key, cosa impossibile da fare se si usa il codice principale) e poi esegue normalmente."
    #Divisione dell'output della hash function in 4 parti da 96 bit ed in 1 da 128 bit per la seguente generazione delle tabelle di permutazione e del vettore Key Stream
    k1= d[0:96]
    k2= d[96:192]
    k3= d[192:288]
    k4= d[288:384]
    k5= d[384:512]

    #genero le tabelle di permutazione
    perm1=RC4_KSA(k1,12)
    perm2=RC4_KSA(k2,12)
    perm3=RC4_KSA(k3,12)
    perm4=RC4_KSA(k4,12)

    V = []
    V.append(xorshift64(np.uint64(int(k5[0:64],2))))
    V.append(xorshift64(np.uint64(int(k5[64:128],2))))
    for i in range (2,NUMBER_OF_WORDS):
        V.insert(i, xorshift64(V[i-2]))
    
    #trasformo il messaggio in una stringa in binario
    msg = ''.join(format(x, 'b').zfill(WORD_PRECISION) for x in bytearray(msg, 'utf-8'))

    #calcolo il numero di blocchi che andrò a formare
    nb=(len(msg))/H
    if type(nb)==float: 
        nb = int(nb+1)
    #creo i blocchi
    b = block_creation(msg,H,nb)
    #applico LESCA
    res = round_func(b, V, perm1, perm2, perm3, perm4, nb)
    #ritorno il messaggio criptato
    return trim(''.join(res))

secret = str(bin(secrets.randbits(512))[2:])
key_1 = []
key_2 = []
ciph_1 = []
ciph_2 = []
#VERSIONE A 64 BIT
msg = '0' * (10240*8)
for j in range(0,1000):
    #creo session key
    key = shared_key_creation()
    key = key.hex()
    key = bin(int(key,16))[2:]
    #Xor tra il segreto e la Session Key
    seed = xor(secret, key)
    seed = seed.encode('utf-8')
    #Applicazione di SHA3_512 sul risultato della XOR precedente
    K = hashlib.sha3_512()
    K.update(seed)
    d = K.hexdigest()
    d = (bin(int(d, 16)))[2:]
    ran = lesca_encrypt(msg, d)
    #Modifica di un bit randomico della precedente Secret Session Key
    dere = xor(secret,key)
    shuffle = random.randint(0,len(dere)-1)
    dere = list(dere)
    if dere[shuffle] == "1":
        dere[shuffle] = "0"
    else:
        dere[shuffle] = "1"
    dere=''.join(dere)
    dere = dere.encode('utf-8')
    #Applicazione di SHA3_512
    Ke = hashlib.sha3_512()
    Ke.update(dere)
    de = Ke.hexdigest()
    de = (bin(int(de, 16)))[2:]
    den = lesca_encrypt(msg, de)
    #calcolo della percentuale di differenza tra i due ciphertexts
    percent = 0
    for i in range(0, len(ran)):
        if(ran[i]==den[i]):
            percent = percent+1
    key_1.append(round(percent/len(ran),3))

#VERIONE AD 8 BIT
#msg = "0" * (10240*8) #se nella versione a 64 bits la lunghezza del messaggio è diversa, modifichiamo msg
for j in range(0,1000):
    key = shared_key_creation()
    key = key.hex()
    key = bin(int(key,16))[2:]
    
    seed = xor(secret, key)
    seed = seed.encode('utf-8')
    
    K = hashlib.sha3_512()
    K.update(seed)
    d = K.hexdigest()
    d = (bin(int(d, 16)))[2:]
    ran = lesca_encrypt_8(msg, d)

    dere = xor(secret,key)
    shuffle = random.randint(0,len(dere)-1)
    dere = list(dere)
    print(str(j))
    if dere[shuffle] == "1":
        dere[shuffle] = "0"
    else:
        dere[shuffle] = "1"
    dere=''.join(dere)
    dere = dere.encode('utf-8')
    
    Ke = hashlib.sha3_512()
    Ke.update(dere)
    de = Ke.hexdigest()
    de = (bin(int(de, 16)))[2:]
    den = lesca_encrypt_8(msg, de)

    percent = 0
    for i in range(0, len(ran)):
        if(ran[i]==den[i]):
            percent = percent+1
    key_2.append(round(percent/len(ran),3))

#DIFFERENZA TRA I CIPHERTEXT PER LO STESSO MESSAGGIO CON CHIAVE RANDOMICA
#msg = "0" * 10240 #modifica della lunghezza di msg
for j in range(0,1000):
    #PRIMA ESECUZIONE CON CHIAVE RANDOMICA
    key = shared_key_creation()
    key = key.hex()
    key = bin(int(key,16))[2:]
    
    seed = xor(secret, key)
    seed = seed.encode('utf-8')
    
    K = hashlib.sha3_512()
    K.update(seed)
    d = K.hexdigest()
    d = (bin(int(d, 16)))[2:]
    ran = lesca_encrypt(msg, d)
    #SECONDA ESECUZIONE CON CHIAVE RANDOMICA
    key = shared_key_creation()
    key = key.hex()
    key = bin(int(key,16))[2:]
    
    seed = xor(secret, key)
    seed = seed.encode('utf-8')
    
    Ke = hashlib.sha3_512()
    Ke.update(seed)
    de = K.hexdigest()
    de = (bin(int(d, 16)))[2:]
    den = lesca_encrypt(msg, de)

    percent = 0
    for i in range(0, len(ran)):
        if(ran[i]==den[i]):
            percent = percent+1
    ciph_1.append(round(percent/len(ran),3))

#VERIONE AD 8 BIT
#msg = "0" * (10240*8) #modifica di msg se non della dimensione desiderata
for j in range(0,1000):
    key = shared_key_creation()
    key = key.hex()
    key = bin(int(key,16))[2:]

    seed = xor(secret, key)
    seed = seed.encode('utf-8')

    K = hashlib.sha3_512()
    K.update(seed)
    d = K.hexdigest()
    d = (bin(int(d, 16)))[2:]
    ran = lesca_encrypt_8(msg, d)

    key = shared_key_creation()
    key = key.hex()
    key = bin(int(key,16))[2:]

    seed = xor(secret, key)
    seed = seed.encode('utf-8')

    Ke = hashlib.sha3_512()
    Ke.update(seed)
    de = K.hexdigest()
    de = (bin(int(d, 16)))[2:]
    den = lesca_encrypt_8(msg, de)

    percent = 0
    for i in range(0, len(ran)):
        if(ran[i]==den[i]):
            percent = percent+1
    ciph_2.append(round(percent/len(ran),3))

bins = [0.490, 0.491, 0.492, 0.493, 0.494, 0.495, 0.496, 0.497, 0.498, 0.499, 0.5, 0.501, 0.502, 0.503, 0.504, 0.505, 0.506, 0.507, 0.508]
#KEY SENSITIVITY - 64 BITS
plt.hist(key_1, bins, range, color = 'green',
        histtype = 'bar', edgecolor="black")
plt.locator_params(axis='x', nbins=19)
plt.xlabel('Percentage of change')
plt.ylabel('Frequency')
plt.title('Key sensitivity graph for 1000 random keys - 64 bits version')
plt.show()

#KEY SENSITIVITY - 8 BITS
plt.hist(key_2, bins, range, color = 'green',
        histtype = 'bar', edgecolor="black")
plt.locator_params(axis='x', nbins=19)
plt.xlabel('Percentage of change')
plt.ylabel('Frequency')
plt.title('Key sensitivity graph for 1000 random keys - 8 bits version')
plt.show()

#CIPHERTEXT DIFFERENCE BETWEEN TWO RANDOM SK - 64 BITS
plt.hist(ciph_1, bins, range, color = 'green',
        histtype = 'bar', edgecolor="black")
plt.locator_params(axis='x', nbins=19)
plt.xlabel('Percentage of change')
plt.ylabel('Frequency')
plt.title('Ciphertext Difference graph for 1000 random keys - 64 bits version')
plt.show()

#CIPHERTEXT DIFFERENCE BETWEEN TWO RANDOM SK - 8 BITS
plt.hist(ciph_2, bins, range, color = 'green',
        histtype = 'bar', edgecolor="black")
plt.locator_params(axis='x', nbins=19)
plt.xlabel('Percentage of change')
plt.ylabel('Frequency')
plt.title('Ciphertext Difference graph for 1000 random keys - 8 bits version')
plt.show()