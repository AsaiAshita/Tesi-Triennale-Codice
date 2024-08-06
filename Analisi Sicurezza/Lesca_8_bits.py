import numpy as np
import secrets
import hashlib
from shared_session_key import shared_key_creation

#COSTANTI (nel caso, da spostare, ma sono utili qui)
DELTA = 4 #arbitrario, decide dopo quanti blocchi cambiare le primitive
NUMBER_OF_WORDS = 4 #costante per numero di parole per blocco, inteso in caratteri (h, invece, lo intende in numero di bit)
H=64*NUMBER_OF_WORDS #64 bit * NUMBER_OF_WORDS (numero di parole per blocco)
WORD_PRECISION = 64 #costante per la bit word precision a cui vogliamo convertire il testo.

_xormap = {('0', '1'): '1', ('1', '0'): '1', ('1', '1'): '0', ('0', '0'): '0'}
def xor(x, y):
    "Funzione che effettua la XOR tra due stringhe usando una map."
    return ''.join([_xormap[a, b] for a, b in zip(x, y)])

def trim(msg):
    res = []
    for i in range(1, int((len(msg)/WORD_PRECISION))+1):
        a = msg[(i*WORD_PRECISION)-8:i*WORD_PRECISION]
        res.append(a)
    return ''.join(res)

def restore(msg):
    res = []
    for i in range(0,int(len(msg)/8)):
        res.append("0"*(64-8) + msg[i*8:(i+1)*8])
    return ''.join(res)

def initialization(secret, key):
    #trasformiamo la session key in una sequenza di bit
    key = key.hex()
    key = bin(int(key,16))[2:]
    #Xor tra il segreto e la Session Key
    seed = xor(secret, key)
    seed = seed.encode('utf-8')

    #Applicazione di Keccack (SHA3_512) sul risultato della XOR precedente
    K = hashlib.sha3_512()
    K.update(seed)
    d = K.hexdigest()
    d = (bin(int(d, 16)))[2:]

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

    #genero il key-stream V (NB: qui assumo che h sia maggiore di 2 e spezzo k5 in due per usare effettivamente ambedue le parti da 64 bits, altrimenti avrei potuto dare k5 in pasto direttamente a xorshift, ma avrebbe eliso determinati bits)
    V = []
    V.append(xorshift64(np.uint64(int(k5[0:64],2))))
    V.append(xorshift64(np.uint64(int(k5[64:128],2))))
    for i in range (2,NUMBER_OF_WORDS):
        V.insert(i, xorshift64(V[i-2]))
    
    return V, perm1, perm2, perm3, perm4

def RC4_KSA (key,length):
    "Funzione che genera le tabelle di permutazione contenenti valori da 0 a NUMBER_OF_WORDS. Prima inizializza la tabella con tali valori, poi la perturba usando key come elemento per generare confusione."
    S = []
    for i in range(0,NUMBER_OF_WORDS):
        S.append(i)
    j = 0
    for i in range(0,NUMBER_OF_WORDS):
        j = (j + S[i] + ord(key[j%length]))%NUMBER_OF_WORDS
        x = S[i]
        S[i] = S[j]
        S[j] = x
    return S

def block_creation(plain, h, nb):
    "Funzione che suddivide il plaintext in nb blocchi di lunghezza h."
    block = []
    point = 0
    end = h
    for i in range(0,nb):
        block.append(plain[point:end])
        point = point + h
        end = end + h
    return block

def xorshift64(t):
    "PRNG efficiente, effettua shift logici a destra e a sinistra del valore t in input e ritorna il valore così ottenuto."
    x=np.uint64(t)
    x = np.uint64(x) ^ (np.uint64(x) >> np.uint64(12))
    x = np.uint64(x) ^ (np.uint64(x) << np.uint64(25))
    x = np.uint64(x) ^ (np.uint64(x) >> np.uint64(27))
    return x

def ROR(V,offset):
    "Funzione che implementa la rotazione a destra del vettore key stream."
    V = (V >> np.uint64(offset)) | (V << (np.uint64(64) - np.uint64(offset)))
    return V

def ROL(V,offset):
    "Funzione che implementa la rotazione a sinistra del vettore di key stream,"
    V = (np.uint64(V) << np.uint64(offset)) | (np.uint64(V) >> (np.uint64(64) - np.uint64(offset)))
    return V

def R(V, Value1, Value2):
    "Funzione di update del vettore di key stream, definita in Speck cipher, per cui perturbiamo il valore di V effettuando operazioni semplici usando V stesso, Value1 e Value2."
    V = np.uint64(ROR(V, 8))
    V = np.uint64(V) + np.uint64(Value1)
    V = np.uint64(V) ^ np.uint64(Value2)
    Value1 = np.uint64(ROL(Value1, 3))
    Value1 = np.uint64(Value1) ^ np.uint64(V)
    return V

def permutation(perm1, perm2):
    "Funzione che genera la permutazione delle tabelle usate in LESCA. In base al valore di perm2 in posizione i, sposto il valore di perm1 a destra con x=perm2[i], creando così una permutazione. Se ho già scritto un valore nella cella, scorro la lista a destra fino a quando non trovo una cella vuota e metto lì il valore."
    res = [-1]*len(perm1)
    for i in range (0,len(perm2)):
        if res[(i+perm2[i])%len(perm1)] != -1:
            offset = 1
            while res[(i+perm2[i]+offset)%len(perm1)] != -1:
                offset = offset + 1
            res[(i+perm2[i]+offset)%len(perm1)] = perm1[i]
        else:
            res[(i+perm2[i])%len(perm1)] = perm1[i]
    return res
            

def update_procedure(V, perm1, perm2, perm3, perm4):
    "Funzione che effettua l'update del vettore di key stream e delle varie tabelle di permutazione grazie alla funzione R ed alla funzione permutation. Chiamata da round_func quando j=DELTA."
    for i in range(0, NUMBER_OF_WORDS):
        V[i] = R(V[i], V[perm1[i]], V[perm2[i]])
    #attuiamo una permutazione delle varie tabelle usando i valori contenuti nel secondo argomento per perturbare gli elementi della prima
    perm1 = permutation(perm1,perm3)
    perm2 = permutation(perm2, perm4)
    perm3 = permutation(perm3,perm4)
    return V, perm1, perm2, perm3

def round_func (plain, V, perm1, perm2, perm3, perm4, nb):
    """Funzione che implementa l'encryption e la decryption di LESCA. Per j tra 1 ed nb+1, se j==DELTA chiamiamo update_procedure, 
    altrimenti creiamo un vettore X di dim(X)==dim(V) tramite xor degli elementi di V seguendo questa formula: V[j]^V[perm1[j]]^V[perm2[j]].
    Poi, per ogni elemento di X, iteriamo xorshift64 su di esso e lo assegniamo a V in posizione q, quindi ruotiamo a destra ciascuno di questi valori
    usando ROR ed infine inseriamo in una lista il ciphertext ottenuto dalla xor tra il blocco di plaintext in posizione j ed il corrispondente vettore di key stream."""
    c =[]
    for j in range(1,nb+1):
        #se j%delta==0, allora è tempo di aggiornare le primitive crittografiche, cosa che viene fatta da update_procedure
        if j%DELTA == 0:
            V,perm1,perm2,perm3 = update_procedure(V, perm1, perm2, perm3, perm4)
        #usiamo il key stream V con le tabelle di permutazione per ottenere un ciphertext seguendo questo metodo
        # 1. XOR tra la posizione j-1 del key stream, della prima tabella di permutazione e della seconda tabella di permutazione: ripeti g volte, dove g=dim(V)
        # 2. Usiamo il valore calcolato precedentemente come seed per un PRNG, che ci dà un valore intermedio per il key stream in posizione J. Applichiamo questo processo a tutti i membri di X, ovvero g=dim(X)=dim(V)
        # 3. Ruotiamo ogni elemento del vettore key stream usando la prima tabella di permutazione per ottenere il valore finale di V in posizione j
        # 4. inseriamo nella lista C il ciphertext ottenuto tramite XOR tra il plaintext ed il valore V[j] ottenuto precedentemente
        X = np.zeros(NUMBER_OF_WORDS, np.uint64)
        for k in range(0,NUMBER_OF_WORDS):
          X = np.insert(X, np.uint64(k), np.uint64(np.uint64(V[k]) ^ np.uint64(V[perm1[k]]) ^ np.uint64(V[perm2[k]]))) 
        for q in range(0, NUMBER_OF_WORDS):
            V[q] = xorshift64(X[q])
        for l in range(0, NUMBER_OF_WORDS):
            V[l] = ROR(V[l],perm1[l])
        intermediate = plain[j-1]
        resulting_text = []
        #applica la XOR tra il valore contenuto in V in posizione j ed il plaintext j: len(intermediate)/64 gestisce il caso in cui nell'ultimo blocco non ci siano esattamente h blocchi, ma di meno, il casting ad int è necessario per far funzionare il tutto, altrimenti, se il valore è float, il codice non funziona
        for m in range (0,int((len(intermediate)/WORD_PRECISION))):
            resulting_text.append(xor(intermediate[m*WORD_PRECISION:(m+1)*WORD_PRECISION], bin(V[j%NUMBER_OF_WORDS])[2:].zfill(WORD_PRECISION)))
        c.insert(j-1, "".join(resulting_text))
    #ritorniamo la lista
    return c

def lesca_encrypt_8(msg, V, perm1, perm2, perm3, perm4):
    #trasformo il messaggio in una stringa in binario
    msg = ''.join(format(x, 'b').zfill(WORD_PRECISION) for x in bytearray(msg, 'latin-1'))

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

def lesca_decrypt(msg, V, perm1, perm2, perm3, perm4):
    #calcolo il numero di blocchi che andrò a formare
    msg = restore(msg)
    nb=(len(msg))/H
    if type(nb)==float: 
        nb = int(nb+1)
    #creo i blocchi
    b = block_creation(msg,H,nb)
    #applico LESCA
    res = round_func(b, V, perm1, perm2, perm3, perm4, nb)
    #faccio parsing dell'output di LESCA per riottenere la stringa originale
    res = ''.join(res)
    final_string = []
    for i in range (1,int(len(res)/WORD_PRECISION)+1):
        a = res[(i*WORD_PRECISION)-8:i*WORD_PRECISION]
        final_string.append(chr(int(a, 2)))
    return ''.join(final_string)