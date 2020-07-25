#BETA-VERSION
#
#Woodnet-SecNetwork-Client
#Autor: Pulsar
#
import socket,os,time,sys
from cryptography.fernet import Fernet 
from colorama import init,Fore,Style
from datetime import datetime 

def gettime():
    n = datetime.now()
    now = "%s:%s:%s"%(n.hour,n.minute,n.second)
    return now

#Farben
init()
w = Style.BRIGHT + Fore.WHITE 
r = Style.BRIGHT + Fore.RED 
c = Style.BRIGHT + Fore.CYAN
y = Fore.YELLOW 
g = Style.BRIGHT + Fore.GREEN
#

print(w+"["+c+"%s"%(gettime())+w+"] ["+g+"INFO"+w+"]"+g+" Autor:"+w+" Pulsar")
print(w+"["+c+"%s"%(gettime())+w+"] ["+g+"INFO"+w+"]"+g+" Python-Version:"+w+" 3.8.2\n\n")

Port = 501
os.system("cls") #Windows -default
s = socket.socket(socket.AF_INET,socket.SOCK_STREAM) #TCP
s.bind(("[EIGENE IP]", int(Port))) # --> BITTE AUSFÜLLEN!!
print("\n\n")
sys.stdout.write(w+"\r["+c+"%s" % (gettime())+w+"] ["+g+"INFO"+w+"]"+g+" Verbindung wird zum Server hergestellt..")
sys.stdout.flush()
try:
    s.connect(("[SERVER-IP]", 8844)) # --> BITTE AUSFÜLLEN!!
    print(w+"["+g+"verbunden"+w+"]")
except Exception as e:
    print(e)
    print(w+"["+r+"fehlgeschlagen"+w+"]")
    s.close()
    quit()
key_s = 'sec/830"asdf3402348973JD#FHAFBI!"§&/$%()*+~'
k = input(w+"\n\nCrypt_Key=>"+r+" ")
key = k.encode()
f = Fernet(key)
key_sb = key_s.encode()
sys.stdout.write(w+"\r["+c+"%s" % (gettime())+w+"] ["+g+"INFO"+w+"]"+g+" Passwort wird gesendet..")
sys.stdout.flush()
pkg = f.encrypt(key_sb)
try:
    s.send(pkg)
    print(w+"["+g+"gesendet"+w+"]")
except:
    print(w+"["+r+"fehlgeschlagen"+w+"]")
    s.close()
    quit()
sys.stdout.write(w+"\r["+c+"%s"%(gettime())+w+"] ["+g+"INFO"+w+"]"+g+" Warte auf Antwort vom Server..")
sys.stdout.flush()
pkt = s.recv(2048)
msg_d = f.decrypt(pkt)
msg = msg_d.decode("UTF-8")
if (msg == "correct key"):
    print(w+"["+g+"richtiger Schlüssel"+w+"]"+w)
else:
    print(w+"["+r+"richtiger Schlüssel"+w+"]"+w)
    s.close()
    quit()
print(r+"\n\n <<<"+y+"Server-Terminal"+r+">>>\n"+w)
print(w+"\r["+c+"%s" % (gettime())+w+"] [" +g+"INFO"+w+"]"+g+" Status=> "+w+"VERBUNDEN\n\n")
while True:
    command = input(r+"@"+r+"root-server"+w+"$ ")
    pkg = command.encode()
    pkt = f.encrypt(pkg)
    try:
        s.send(pkt)
        if (command == "closeconnection" or command == "stop server"):
            print("\nVerbindung wurde "+r+"geschlossen."+w)
            break
    except:
        print("\nVerbindung mit dem Server ist"+r+" fehlgeschlagen"+w)
        break
    try:
        pkg = s.recv(2048)
    except:
        print("\nVerbindung mit dem Server ist"+r+" fehlgeschlagen"+w)
        break
    pkt = f.decrypt(pkg)
    msg = pkt.decode()
    print("%s"%(msg))
    if (command == "cls" or command == "clear"):
        os.system("cls")  # Windows -default
s.close()
quit()
