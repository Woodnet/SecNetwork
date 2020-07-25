import socket
from threading import Thread
from datetime import datetime
import os
import time
import sys
import time
from cryptography.fernet import Fernet


def accept_incoming_connections():
    while True:
        #print("yep")
        client, client_address = server.accept()
        print("<=[%s:%s]=> hat sich verbunden." % client_address)
        client.send(bytes("Bitte geben deinen Nicknamen ein", "utf8"))
        addresses[client] = client_address
        Thread(target=handle_client, args=(client,)).start()


def decrypt_msg(msg, f):
    decrypted_msg = f.decrypt(msg)
    return decrypted_msg


def handle_client(client):

    name = client.recv(BUFSIZ).decode("utf8")
    print("Prefix=> %s" % (name))
    welcome = 'Willkommen %s! Wenn du die Verbindung wieder trennen willst, gebe bitte {quit} ein.\n' % (
        name)+"\n\n"
    client.send(bytes(welcome, "utf8"))
    msg = "\n=>[%s] hat sich mit dem Socket_Server2 verbunden!\n" % name
    broadcast(bytes(msg, "utf8"))
    clients[client] = name
    crash = False
    while True:
        msg = client.recv(BUFSIZ)
        print(msg.decode())
        if (msg != bytes("{quit}", "utf8") and msg.decode() != "Code_18-Ajkdjvgb032xcyzZcUazuez637flushuebc"):
            broadcast(msg, "    " + "[%s]=> " % (name))
        if (msg == bytes("{quit}", "utf8")):
            #client.send(bytes("{quit}", "utf8"))
            del clients[client]
            print("[%s] hat die Verbindung geschlossen." % name)
            broadcast(
                bytes("%s hat die Verbindung zum Server getrennt.\n" % name, "utf8"))
            client.close()
            quit()
        if (msg.decode() == "Code_18-Ajkdjvgb032xcyzZcUazuez637flushuebc"):
            print("[%s] hat Code 18 gesendet. Server wird herruntergefahren.." % (name))
            #broadcast(bytes("%s Der Server wird herruntergefahren..\n" % name, "utf8"))
            crash = True
        if (crash == True):
            break


def broadcast(msg, prefix=""):
    for sock in clients:
        sock.send(bytes(prefix, "utf8")+msg)


#Server
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # TCP
s_addr = ("192.168.178.35", 3281)
server.bind(s_addr)
clients = {}
addresses = {}
BUFSIZ = 1024
key = b'yRs0TYFDQ4syMZsE0CDPTfOXBqz7D5zbSx3CiWqoa9o='  # SecNetworkServerEncr
f = Fernet(key)
#
if __name__ == "__main__":
    server.listen(10)
    print("Warte auf Clients..[Socket_Server2]")
    ACCEPT_THREAD = Thread(target=accept_incoming_connections)
    ACCEPT_THREAD.start()
    ACCEPT_THREAD.join()
    server.close()
