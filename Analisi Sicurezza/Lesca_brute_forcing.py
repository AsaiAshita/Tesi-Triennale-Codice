import itertools
import time
import os

possibilites = []
solutions =  []
WORD_PRECISION = 8 #precisione in bit del messaggio criptato

_xormap = {('0', '1'): '1', ('1', '0'): '1', ('1', '1'): '0', ('0', '0'): '0'}
def xor(x, y):
    "Funzione che effettua la XOR tra due stringhe usando una map."
    return ''.join([_xormap[a, b] for a, b in zip(x, y)])

def combinations(l, wp):
     yield from itertools.product(*([l] * wp)) 


encrypted = '0111101001111110' # [= ok], in versione ad 8 bit (lunghezza = 16 bit). Modificare questo elemento per provare vari casi di brute force attack
start_time = time.time()
for x in combinations('01', len(encrypted)):
     possibilites.append(''.join(x))
print("TIME NEEDED FOR COMBINATIONS: ", start_time-time.time())

start_time = time.time()
for x in possibilites:
     solutions.append(xor(encrypted, x))
print("TIME NEEDED FOR XORING ALL POSSIBILITIES: ", start_time-time.time())

start_time = time.time()
possible_strings = []
for x in solutions:
    final_string = []
    for i in range (1,int(len(x)/WORD_PRECISION)+1):
        a = x[i*WORD_PRECISION-WORD_PRECISION:i*WORD_PRECISION]
        final_string.append(chr(int(a, 2)))
    possible_strings.append(''.join(final_string))
print("TIME NEEDED FOR CREATING SOLUTIONS: ", start_time-time.time())

dir = os.path.dirname(os.path.realpath(__file__))
print(dir)
f = open(dir + "\solutions_lesca_brute_force_attack.txt", "a", encoding="utf-8")
for i in range(0, len(possible_strings)):
     f.write(possible_strings[i] + "\n")
f.close()
   