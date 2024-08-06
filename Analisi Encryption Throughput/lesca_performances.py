import time
from Lesca_8_bits import lesca_encrypt, initialization #per fare average encryption throughput sulla versione mista
#from Lesca import lesca_encrypt, initialization #per fare average encryption throughput sulla versione a 64 bits
from shared_session_key import shared_key_creation
import secrets

def testing(through_1, msg, bytes_encrypted):
    key = shared_key_creation()
    V, perm1, perm2, perm3, perm4 = initialization(secret, key)
    for i in range(0, 1000):
        start_time = time.time()
        res = lesca_encrypt(msg, V, perm1, perm2, perm3, perm4)
        finish_time = time.time()-start_time
        through_1[i] = bytes_encrypted/finish_time
    return through_1

secret = str(bin(secrets.randbits(512))[2:])
length = 7 #se non si vuole eseguire ogni volta il programma per ogni lunghezza, basta mettere un ciclo for della lunghezza desiderata
msg = "0" * (pow(2, length) * 8) #moltiplicazione per 8 perchè stiamo considerando bytes, non bits
through_1 = [0] * 1000
bytes_encrypted = pow(2,length)
through_1 = testing(through_1, msg, bytes_encrypted)
throughput = 0
for i in range(0, len(through_1)):
    throughput = throughput+through_1[i]
final_throughput = throughput/len(through_1)
print("AVERAGE ENCRYPTION THROUGHPUT = ", final_throughput)

    
