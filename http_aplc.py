import socket

http_server_ip = "127.0.0.1"
http_server_port = 20820

client_ip = None
client_port = 8002


def http_request_handler(client_sock, client_addr):
    global client_ip, client_port
    print("Received connection from:", client_addr)

    # Receive data from the client
    client_data = client_sock.recv(1024)

    if client_data:
        # Extract the HTTP request from the client data
        http_request = client_data.decode()

        if not client_ip or not client_port:
            client_ip = client_addr[0]
            client_port = client_addr[1]

        if http_request.startswith("GET"):
            print("Received GET request: {}".format(http_request))

            # Extract the requested path from the HTTP request
            path = http_request.split(" ")[1]

            if path == "/home/evyatar/Desktop/end project/image.jpg":
                # Send a GET request to the HTTP server to get the image
                http_request = "GET /image.jpg HTTP/1.1\r\n"
                server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                server_sock.connect((http_server_ip, http_server_port))
                server_sock.sendall(http_request.encode())

                # Receive the response from the HTTP server
                server_response = server_sock.recv(1024)

                if server_response:
                    
                    # Send the image to the client
                    client_sock.sendall(server_response)
                else:
                    # Return a 404 Not Found response
                    http_response = "HTTP/1.1 404 Not Found\r\n\r\n".encode()
                    client_sock.sendall(http_response)
            else:
                # Return a 404 Not Found response
                http_response = "HTTP/1.1 404 Not Found\r\n\r\n".encode()
                client_sock.sendall(http_response)
        else:
            # Return a 400 Bad Request response
            http_response = "HTTP/1.1 400 Bad Request\r\n\r\n".encode()
            client_sock.sendall(http_response)

        # Close the client socket
        client_sock.close()


def main():
    print("Starting HTTP server...")
    server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_sock.bind(('localhost', 20820))
    server_sock.listen(1)

    while True:
        client_sock, client_addr = server_sock.accept()
        http_request_handler(client_sock, client_addr)


if __name__ == "__main__":
    main()
