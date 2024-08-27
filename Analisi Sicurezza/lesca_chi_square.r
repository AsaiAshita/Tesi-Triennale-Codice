#CODE USED TO TEST CHI-SQUARE FOR GOODNESS OF FIT
obs <- c() #inserire dentro c i risultati dati da lesca_statistical.py per il caso che si vuole valutare
#Numero totale di valori possibili
size <- length(obs)
#creiamo un vettore di probabilità uniformi
exp <- c(rep((1/size), size))
#otteniamo il valore del chi-square test critico per alpha = 0.05 
qchisq(p = 0.95, df = 255)
#eseguiamo Chi-square test for Goodness of fit 
chisq.test(x=obs, p=exp)