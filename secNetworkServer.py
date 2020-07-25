#SecNetworkServer -'Hauptserver' 
#Python 3.8.2
#by Pulsar
#23.07.2020
import socket,os,time
from cryptography.fernet import Fernet 
import sys 
from datetime import datetime 

os.system("cls") #Windows -default

#Verschlüsselung
socket_key = 'sec/830"asdf3402348973JD#FHAFBI!"§&/$%()*+~' #default
key = Fernet.generate_key()
f = Fernet(key) 
#
#Alle Server Adressen
ip_s1 = "localhost"
port_s1 = 5582
ip_s2 = "localhost"
port_s2 = 1337
ip_s3 = "localhost"
port_s3 = 3281
s1 = (ip_s1, port_s1)  # Chatserver     => LOCALHOST - default
s2 = (ip_s2, port_s2)  # Socket_Server  => LOCALHOST - default
s3 = (ip_s3, port_s3)  # Socket_Server2 => LOCALHOST - default
#
#Socket
def set_s():
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP
    return s
    
def set_s_addr():
    s_addr = (("192.168.178.35", 8844))  # => LOCALHOST - default
    return s_addr
#
#Variabeln
count = 0
conn_counter = 0
crash = False 
b_size = 1048
errors = 0
file = open("moneyfile.secnetwork.mny","r")
money = file.read()
file.close()
#
#Logs
logfilename = "logfile.secnetwork"
blacklistfilename = "blacklist.secnetwork"
commandsfilename = "commandsfile.secnetwork"
serverstatusfilename = "serverstatus.secnetwork"
#
#Kommandos 
commands = [
    "help",
    "stop server",
    "start chatserver",
    "closeconnection",
    "showlogs",
    "sh status servers",
    "start socketserver1",
    "start socketserver2",
    "stop socketserver1",
    "stop socketserver2",
    "get addr socketserver1",
    "get addr socketserver2",
    "get cryptkey",
    "money"
]
#

def gettime():
    n = datetime.now()
    now = "%s:%s:%s"%(n.hour,n.minute,n.second)
    return now 

def decrypt(encr_msg,f):
    try:
        msg = f.decrypt(encr_msg)
        decr_msg = msg.decode()
    except:
        print(" [%s] [KRITISCH] Die Nachricht konnte nicht entschlüsselt werden!" % (gettime()))
        print(" [%s] [KRITISCH] Es wird eine andere Verschlüsselung genutzt!" % (gettime()))
        print(" [%s] [INFO] Server wird neugestartet.." % (gettime()))
        decr_msg = False 
    
    return decr_msg

def encrypt(decr_msg,f):
    msg = decr_msg.encode()
    encr_msg = f.encrypt(msg)
    return encr_msg


def encrypt_socket_server1(decr_msg,f_socket_server1):
    msg = decr_msg.encode()
    encr_msg = f.encrypt(msg)
    return encr_msg

#Server Klasse
class server:
    def __init__(self, count, b_size, errors, s_addr, s, crash, socket_key, f, key, commands, conn_counter, logfilename, blacklistfilename, commandsfilename, s1, s2, s3, serverstatusfilename,ip_s1,port_s1,ip_s2,port_s2,ip_s3,port_s3,money):
        self.count = count 
        self.money = money
        self.logfilename = logfilename
        self.b_size = b_size 
        self.conn_counter = conn_counter
        self.errors = errors 
        self.s_addr = s_addr
        self.s = s
        self.blacklistfilename = blacklistfilename
        self.crash = crash
        self.socket_key = socket_key
        self.f = f
        self.key = key 
        self.commands = commands
        self.commandsfilename = commandsfilename
        self.s1 = s1 
        self.s2 = s2
        self.s3 = s3 
        self.serverstatusfilename = serverstatusfilename
        self.ip_s1 = ip_s1 
        self.ip_s2 = ip_s2
        self.ip_s3 = ip_s3
        self.port_s1 = port_s1
        self.port_s2 = port_s2
        self.port_s3 = port_s3

    def create_socket(self):
        print(" [%s] [INFO] Server wird gestartet" %(gettime()))
        print(" [%s] [INFO] Gemeldete Fehler: %s"%(gettime(),self.errors))
        print(" [%s] [INFO] Verschlüsselung=> %s"%(gettime(),self.key.decode()))
        print(" [%s] [INFO] Binding Adresse.."%(gettime()))
        try:
            self.s.bind(self.s_addr)
        except socket.error:
            self.errors += 1
            print(" [%s] [KRITISCH] Die Adresse konnte nicht gebindet werden!"%(gettime()))
            self.crash = True
        if (self.crash == True):
            print(" [%s] [INFO] Server wurde mit %s Fehler gestoppt."%(gettime(),self.errors))
            quit()
        print(" [%s] [INFO] Warte auf Client..."%(gettime()))
        self.s.listen(1)
        (client,addr) = self.s.accept()
        print(" [%s] [INFO] Suche IP in den Logs.."%(gettime()))
        file = open(logfilename, "r")
        logs = file.read()
        if (str(addr) in logs):
            print(" [%s] [INFO] %s wurde in den Logs gefunden"%(gettime(),str(addr)))
            print(" [%s] [INFO] Prüfe, ob die IP in der Blacklist ist.." % (gettime()))
            file.close()
            file = open(self.blacklistfilename,"r")
            blacklist = file.read()
            if (str(addr) in blacklist):
                print(" [%s] [WARNING] IP wurde in der Blacklist vermerkt!" % (gettime()))
                print(" [%s] [WARNING] Verbindung wird verweigert.." % (gettime()))
                client.close()
                print(" [%s] [WARNING] Verbindung wurde zu %s geschlossen"%(gettime(),str(addr)))
                print(" [%s] [INFO] Server wird neugestartet.." % (gettime()))
                self.s.close()
                time.sleep(2)
                ser.create_socket()
            else:
               print(" [%s] [INFO] Die IP ist nicht in der Blacklist vermerkt"%(gettime()))
        else:
            print(" [%s] [INFO] IP hat sich noch nie mit dem Server verbunden" % (gettime()))
            sys.stdout.write(" [%s] [INFO] IP wird in den LOGS vermerkt.." % (gettime()))
            sys.stdout.flush()
            file.close()
            file = open(logfilename, "a")
            file.write("\n%s"%(str(addr)))
            file.close()
            print("[vermerkt]")

        self.client = client 
        self.addr = addr 
        print(" [%s] [INFO] Eine Verbindung wurde hergestellt" % (gettime()))
        print(" [%s] [INFO] Verbindung von -> %s" % (gettime(),str(addr)))
        
    def run_server(self):
        print(" [%s] [INFO] Warten auf Passwort.." % (gettime()))
        try:
            resp_encr = self.client.recv(self.b_size)
            if (decrypt(resp_encr, self.f) == False):
                print(" [%s] [INFO] Server wird neugestartet.." % (gettime()))
                self.crash = True
            if (self.crash == True):
                self.s.close()
                ser.create_socket()
        except socket.error:
            self.errors += 1
            print(" [%s] [INFO] Die Verbindung wurde unterbrochen" % (gettime()))
            print(" [%s] [INFO] Server wird neugestartet.." % (gettime()))
            self.crash = True
        if (self.crash == True):
            self.s.close()
            ser.create_socket()
        print(" [%s] [INFO] Verschlüsseltes Passwort wurde empfangen" % (gettime()))
        if (decrypt(resp_encr, self.f) == self.socket_key):
            print(" [%s] [INFO] Richtiges Passwort von %s" % (gettime(),str(self.addr)))
        else:
            print(" [%s] [KRITISCH] Falsches Passwort von %s" % (gettime(),str(self.addr)))
            print(" [%s] [INFO] Verbindung zum Client wird geschlossen.." % (gettime()))
            self.client.close()
            print(" [%s] [INFO] Server wird neugestartet.." % (gettime()))
            self.crash = True
        if (self.crash == True):
            self.s.close()
            ser.create_socket()
        sys.stdout.write("\r [%s] [INFO] Nachricht wird verschlüsselt.."%(gettime()))
        sys.stdout.flush()
        msg = "correct key" #default => Kann geändert werden (!BEACHTE!: Der Client muss angepasst werden)
        encr_msg = encrypt(msg,self.f)
        print("[verschlüsselt]")
        sys.stdout.write("\r [%s] [INFO] Nachricht wird versendet.." % (gettime()))
        sys.stdout.flush()
        try:
            self.client.send(encr_msg)
            print("[gesendet]")
        except socket.error:
            print("[FEHLER]")
            self.errors += 1
            print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden"%(gettime()))
            print(" [%s] [KRITISCH] Verbindung wurde unterbrochen.")
            print(" [%s] [INFO] Server wird neugestartet.."%(gettime()))
            self.crash = True
        if (self.crash == True):
            self.s.close()
            ser.create_socket()
        while (self.crash == False):
            print(" [%s] [INFO] Warte auf Commands vom Client.."%(gettime()))
            resp_encr = self.client.recv(self.b_size)
            print(" [%s] [INFO] Das Packet wurde von %s empfangen"%(gettime(),str(self.addr)))
            if (decrypt(resp_encr, self.f) in self.commands):
                if (decrypt(resp_encr, self.f) == self.commands[0]):
                    print(" [%s] [INFO] 'help'-Command wurde ausgewählt" % (gettime()))
                    file = open(self.commandsfilename,"r")
                    msg = file.read()
                    sys.stdout.write("\r [%s] [INFO] Nachricht wird verschlüsselt.." % (gettime()))
                    sys.stdout.flush()
                    encr_msg = encrypt(msg, self.f)
                    print("[verschlüsselt]")
                    sys.stdout.write("\r [%s] [INFO] Nachricht wird gesendet.." %(gettime()))
                    sys.stdout.flush()
                    try:
                        self.client.send(encr_msg)
                        print("[gesendet]")
                    except socket.error:
                        print("[FEHLER]")
                        self.errors += 1
                        print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                        print(" [%s] [KRITISCH] Verbindung wurde unterbrochen.")
                        print(" [%s] [INFO] Server wird neugestartet.." % (gettime()))
                        self.crash = True
                if (decrypt(resp_encr, self.f) == self.commands[1]):
                    print(" [%s] [INFO] Server wird auf Anweisung vom Client -> %s gestoppt" % (gettime(),str(self.addr)))
                    self.client.close()
                    self.s.close()
                    self.crash = False
                    break
                if (decrypt(resp_encr, self.f) == self.commands[2]):
                    print(" [%s] [INFO] Chatserver wird auf Anweisung vom Client -> %s gestartet.." % (gettime(),str(self.addr)))
                    os.system("start runchatserver.bat")
                    msg = "wird gestartet"
                    encr_msg = encrypt(msg, self.f)
                    sys.stdout.write("\r [%s] [INFO] Nachricht wird versendet.."%(gettime()))
                    sys.stdout.flush()
                    try:
                        self.client.send(encr_msg)
                        print("[gesendet]")
                    except socket.error:
                        print("[FEHLER")
                        self.errors += 1
                        print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                        print(" [%s] [KRITISCH] Verbindung wurde unterbrochen.")
                        print(" [%s] [INFO] Server wird neugestartet.." %(gettime()))
                        self.crash = True
                if (decrypt(resp_encr, self.f) == self.commands[3]):
                    print(" [%s] [INFO] Die Verbindung wird vom Client -> %s geschlossen"%(gettime(),str(self.addr)))
                    self.crash = True
                if (decrypt(resp_encr, self.f) == self.commands[4]):
                    print(" [%s] [INFO] 'showlogs'-Kommando wird benutzt"%(gettime()))
                    file = open(self.logfilename,"r")
                    logs = file.read()
                    encr_msg = encrypt(logs,self.f)
                    file.close()
                    try:
                        self.client.send(encr_msg)
                        print("[gesendet]")
                    except socket.error:
                        print("[FEHLER]")
                        self.errors += 1
                        print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                        print(" [%s] [KRITISCH] Verbindung wurde unterbrochen."%(datetime()))
                        print(" [%s] [INFO] Server wird neugestartet.."%(gettime()))
                        self.crash = True
                if (decrypt(resp_encr, self.f) == self.commands[5]):
                    print(" [%s] [INFO] 'sh status servers'-Kommando wird benutzt"%(gettime()))
                    print(" [%s] [INFO] Rufe Status von allen Servern ab.."%(gettime()))
                    file = open(serverstatusfilename,"w")
                    try:
                        status = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP
                        status.connect(self.s1)
                        s1_st = True
                    except:
                        s1_st = False
                    if (s1_st == True):
                        print(" [%s] [INFO] Chatserver ist online" % (gettime()))
                        file.write("  Chatserver ist [ONLINE]")
                        msg = "NICKNAME"
                        pkg = msg.encode()
                        status.send(pkg)
                        time.sleep(3)
                        msg = "{quit}"
                        pkg = msg.encode()
                        status.send(pkg) 
                        status.close()
                    else:
                        print(" [%s] [INFO] Chatserver ist offline"%(gettime()))
                        file.write("  Chatserver ist [offline]")
                    try:
                        status = socket.socket(
                            socket.AF_INET, socket.SOCK_STREAM)  # TCP
                        status.connect(self.s2)
                        s2_st = True
                    except:
                        s2_st = False
                    if (s2_st == True):
                        print(" [%s] [INFO] Socket-Server1 ist online"%(gettime()))
                        file.write("\n  Socket-Server1 ist [ONLINE]")
                        msg = "NICKNAME"
                        pkg = msg.encode()
                        status.send(pkg)
                        time.sleep(3)
                        msg = "{quit}"
                        pkg = msg.encode()
                        status.send(pkg)
                        status.close()
                    else:
                        print(" [%s] [INFO] Socket-Server1 ist offline"%(gettime()))
                        file.write("\n  Socket-Server1 ist [offline]")
                    try:
                        status = socket.socket(
                            socket.AF_INET, socket.SOCK_STREAM)  # TCP
                        status.connect(self.s3)
                        s3_st = True
                    except:
                        s3_st = False
                    if (s3_st == True):
                        print(" [%s] [INFO] Socket-Server2 ist online" %(gettime()))
                        file.write("\n  Socket-Server2 ist [ONLINE]")
                        msg = "NICKNAME"
                        pkg = msg.encode()
                        status.send(pkg)
                        time.sleep(3)
                        msg = "{quit}"
                        pkg = msg.encode()
                        status.send(pkg)
                        status.close()
                    else:
                        print(" [%s] [INFO] Socket-Server2 ist offline"%(gettime()))
                        file.write("\n  Socket-Server2 ist [offline]")
                    file.close()
                    file = open(serverstatusfilename,"r")
                    serverstatus = file.read()
                    encr_msg = encrypt(serverstatus,self.f)
                    file.close()
                    try:
                        self.client.send(encr_msg)
                        print("[gesendet]")
                    except socket.error:
                        print("[FEHLER]")
                        self.errors += 1
                        print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                        print(" [%s] [KRITISCH] Verbindung wurde unterbrochen."%(datetime()))
                        print(" [%s] [INFO] Server wird neugestartet.."%(gettime()))
                        self.crash = True

                if (decrypt(resp_encr, self.f) == self.commands[6]):
                    print(" [%s] [INFO] Client will Socket-Server 1 starten"%(gettime()))
                    sys.stdout.write("\r [%s] [INFO] Server wird gestartet.." % (gettime()))
                    sys.stdout.flush()
                    try:
                        os.system("start startsocket_server1.bat")
                        print("[gestartet]")
                        msg = "Der Socket_Server1 wurde gestartet"
                        encr_msg = encrypt(msg, self.f)
                        try:
                            self.client.send(encr_msg)
                            print("[gesendet]")
                        except socket.error:
                            print("[FEHLER]")
                            self.errors += 1
                            print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                            print(" [%s] [KRITISCH] Verbindung wurde unterbrochen.")
                            print(" [%s] [INFO] Server wird neugestartet.." % (gettime()))
                            self.crash = True
                    except:
                        print("[FEHLER]"%(gettime()))
                        msg = "Socket_Server1 konnte nicht gestartet werden!"
                        encr_msg = encrypt(msg, self.f)
                        try:
                            self.client.send(encr_msg)
                            print("[gesendet]")
                        except socket.error:
                            print("[FEHLER]")
                            self.errors += 1
                            print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                            print(" [%s] [KRITISCH] Verbindung wurde unterbrochen.")
                            print(" [%s] [INFO] Server wird neugestartet.." %(gettime()))
                            self.crash = True
                if (decrypt(resp_encr, self.f) == self.commands[7]):
                    print(" [%s] [INFO] Client will Socket-Server 2 starten"%(gettime()))
                    sys.stdout.write("\r [%s] [INFO] Server wird gestartet.." % (gettime()))
                    sys.stdout.flush()
                    try:
                        os.system("start startsocket_server2.bat")
                        print("[gestartet]")
                        msg = "Der Socket_Server2 wurde gestartet"
                        encr_msg = encrypt(msg, self.f)
                        try:
                            self.client.send(encr_msg)
                            print("[gesendet]")
                        except socket.error:
                            print("[FEHLER]")
                            self.errors += 1
                            print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                            print(" [%s] [KRITISCH] Verbindung wurde unterbrochen.")
                            print(" [%s] [INFO] Server wird neugestartet.." % (gettime()))
                            self.crash = True
                    except:
                        print("[FEHLER]"%(gettime()))
                        msg = "Socket_Server2 konnte nicht gestartet werden!"
                        encr_msg = encrypt(msg, self.f)
                        try:
                            self.client.send(encr_msg)
                            print("[gesendet]")
                        except socket.error:
                            print("[FEHLER]")
                            self.errors += 1
                            print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                            print(" [%s] [KRITISCH] Verbindung wurde unterbrochen.")
                            print(" [%s] [INFO] Server wird neugestartet.." %(gettime()))
                            self.crash = True

                if (decrypt(resp_encr, self.f) == self.commands[8]):
                    print(" [%s] [INFO] %s will den Socket_Server1 herrunterfahren."%(gettime(),str(self.addr)))
                    sys.stdout.write( "\r [%s] [INFO] Der Socket_Server1 wird herruntergefahren.."%(gettime()))
                    sys.stdout.flush()
                    os.system('taskkill /F /FI "WINDOWTITLE eq SocketServer1"')
                    os.system('taskkill /F /FI "WINDOWTITLE eq SocketServer1"')
                    print(" [%s] [INFO] Der Socket_Server1 wurde gestoppt"%(gettime()))
                    msg = "Der Socket_Server1 wurde gestoppt"
                    encr_msg = encrypt(msg, self.f)
                    try:
                        self.client.send(encr_msg)
                        print("[gesendet]")
                    except socket.error:
                        print("[FEHLER]")
                        self.errors += 1
                        print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                        print(" [%s] [KRITISCH] Verbindung wurde unterbrochen.")
                        print(" [%s] [INFO] Server wird neugestartet.." %
                            (gettime()))
                        self.crash = True
                if (decrypt(resp_encr, self.f) == self.commands[9]):
                    print(" [%s] [INFO] %s will den Socket_Server2 herrunterfahren."%(gettime(),str(self.addr)))
                    sys.stdout.write( "\r [%s] [INFO] Der Socket_Server2 wird herruntergefahren.."%(gettime()))
                    sys.stdout.flush()
                    os.system('taskkill /F /FI "WINDOWTITLE eq SocketServer2"')
                    os.system('taskkill /F /FI "WINDOWTITLE eq SocketServer2"')
                    print(" [%s] [INFO] Der Socket_Server2 wurde gestoppt"%(gettime()))
                    msg = "Der Socket_Server1 wurde gestoppt"
                    encr_msg = encrypt(msg, self.f)
                    try:
                        self.client.send(encr_msg)
                        print("[gesendet]")
                    except socket.error:
                        print("[FEHLER]")
                        self.errors += 1 
                        print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                        print(" [%s] [KRITISCH] Verbindung wurde unterbrochen.")
                        print(" [%s] [INFO] Server wird neugestartet.." %(gettime()))
                        self.crash = True
                if (decrypt(resp_encr, self.f) == self.commands[10]):
                    print(" [%s] [INFO] 'get addr socketserver1'-Kommando wird von %s benutzt"%(gettime(),str(self.addr)))
                    sys.stdout.write( "\r [%s] [INFO] Die Adresse vom Socket_Server1 wird abgerufen.."%(gettime()))
                    sys.stdout.flush()
                    msg = "IP: %s | Port: %s" % (self.ip_s1, self.port_s1)
                    #msg = msg_en.encode()
                    print("[IP: %s | Port: %s]"%(self.ip_s1, self.port_s1))
                    encr_msg = encrypt(msg, self.f)
                    try:
                        self.client.send(encr_msg)
                        print("[gesendet]")
                    except socket.error:
                        print("[FEHLER]")
                        self.errors += 1
                        print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                        print(" [%s] [KRITISCH] Verbindung wurde unterbrochen."%(gettime()))
                        print(" [%s] [INFO] Server wird neugestartet.." %(gettime()))
                        self.crash = True
                if (decrypt(resp_encr, self.f) == self.commands[11]):
                    print(" [%s] [INFO] 'get addr socketserver2'-Kommando wird von %s benutzt"%(gettime(),str(self.addr)))
                    sys.stdout.write( "\r [%s] [INFO] Die Adresse vom Socket_Server1 wird abgerufen.."%(gettime()))
                    sys.stdout.flush()
                    msg = "IP: %s | Port: %s" % (self.ip_s2, self.port_s2)
                    #msg = msg_en.encode()
                    print("[IP: %s | Port: %s]" % (self.ip_s2, self.port_s2))
                    encr_msg = encrypt(msg, self.f)
                    try:
                        self.client.send(encr_msg)
                        print("[gesendet]")
                    except socket.error:
                        print("[FEHLER]")
                        self.errors += 1
                        print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                        print(" [%s] [KRITISCH] Verbindung wurde unterbrochen."%(gettime()))
                        print(" [%s] [INFO] Server wird neugestartet.." %(gettime()))
                        self.crash = True
                if (decrypt(resp_encr, self.f) == self.commands[12]):
                    print(" [%s] [INFO] 'get cryptkey'-Kommando wird von %s benutzt"%(gettime(), str(self.addr)))
                    msg = key.decode()
                    encr_msg = encrypt(msg, self.f)
                    sys.stdout.write(" [%s] [INFO] Nachricht wird versendet.." % (gettime()))
                    sys.stdout.flush()
                    try:
                        self.client.send(encr_msg)
                        print("[gesendet]")
                    except socket.error:
                        print("[FEHLER]")
                        self.errors += 1
                        print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                        print(" [%s] [KRITISCH] Verbindung wurde unterbrochen." % (gettime()))
                        print(" [%s] [INFO] Server wird neugestartet.."%(gettime()))
                        self.crash = True
                if (decrypt(resp_encr, self.f) == self.commands[13]):
                    print(" [%s] [INFO] 'money'-Kommando wird von %s benutzt"%(gettime(), str(self.addr)))
                    msg = self.money
                    encr_msg = encrypt(msg, self.f)
                    sys.stdout.write(" [%s] [INFO] Nachricht wird versendet.." % (gettime()))
                    sys.stdout.flush()
                    try:
                        self.client.send(encr_msg)
                        print("[gesendet]")
                    except socket.error:
                        print("[FEHLER]")
                        self.errors += 1
                        print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                        print(" [%s] [KRITISCH] Verbindung wurde unterbrochen." % (gettime()))
                        print(" [%s] [INFO] Server wird neugestartet.." %(gettime()))
                        self.crash = True
                    
            else:   
                print(" [%s] [WARNUNG] Unbekannter Command!" % (gettime()))
                msg = "Unbekannter Command"
                encr_msg = encrypt(msg, self.f)
                sys.stdout.write(" [%s] [INFO] Nachricht wird versendet.." % (gettime()))
                sys.stdout.flush()
                try:
                    self.client.send(encr_msg)
                    print("[gesendet]")
                except socket.error:
                    print("[FEHLER]")
                    self.errors += 1
                    print(" [%s] [KRITISCH] Nachricht konnte nicht versendet werden" % (gettime()))
                    print(" [%s] [KRITISCH] Verbindung wurde unterbrochen."%(gettime()))
                    print(" [%s] [INFO] Server wird neugestartet.." % (gettime()))
                    self.crash = True
        if (self.crash == True):
            print("\n [RESTARTING..]\n")
        else:
            quit()

#Main Loop
while True:
    try:
        s = set_s()
        s_addr = set_s_addr()
        ser = server(count, b_size, errors, s_addr, s, crash, socket_key, f, key,
                     commands, conn_counter, logfilename, blacklistfilename, commandsfilename, s1, s2, s3, serverstatusfilename, ip_s1, port_s1, ip_s2, port_s2, ip_s3, port_s3,money)
        ser.create_socket()
        ser.run_server()
    except KeyboardInterrupt:
        s.close()
        quit()
