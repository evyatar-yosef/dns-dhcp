from scapy.all import *
import time
import os

server_ip = "127.0.0.1"

if __name__ == '__main__':
    server_port = 8001  # server bind
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # bind the socket to a specific address and port
    server_address = ('127.0.0.1', server_port)
    print('starting up on {} port {}'.format(*server_address))
    sock.bind(server_address)

    # listen for incoming connections
    sock.listen(1)

    while True:
        # wait for a connection
        print('waiting for a connection')
        connection, client_address = sock.accept()
        try:
            print('connection from', client_address)

            # receive the request
            data = connection.recv(1024)

            # send the file
            file_path = "/home/evyatar/Desktop/end project/mytext.txt"
            file_size = os.path.getsize(file_path)
            with open(file_path, "rb") as f:
                data = f.read(file_size)
                connection.sendall(data)

            print("done sending file")

        finally:
            # close the connection
            connection.close()
