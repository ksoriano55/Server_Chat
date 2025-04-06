import socket
import threading

HOST = '192.168.1.36'
PORT = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

clients = {}
usernames = {}

def broadcast(message, sender_socket=None):
    for client in clients:
        if client != sender_socket:
            try:
                client.send(message)
            except:
                client.close()
                del clients[client]

def handle_client(client):
    username = client.recv(1024).decode()
    usernames[client] = username
    update_user_list()

    while True:
        try:
            msg = client.recv(1024)
            broadcast(msg, sender_socket=client)
        except:
            print(f"{username} disconnected")
            clients.pop(client, None)
            usernames.pop(client, None)
            client.close()
            update_user_list()
            break

def update_user_list():
    user_list = "USER_LIST:" + ",".join(usernames.values())
    broadcast(user_list.encode())

print("Server is running...")
while True:
    client_socket, addr = server.accept()
    print(f"Connected with {addr}")
    clients[client_socket] = addr
    threading.Thread(target=handle_client, args=(client_socket,)).start()
