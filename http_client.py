import socket
import time
from io import BytesIO
import PIL.Image
import socket
import time

http_server_ip = "127.0.0.1"
http_server_port = 20820

redirected_server_ip = "127.0.0.1"
redirected_server_port = 8001

client_ip = "127.0.0.1"
client_port = 8002

def send_request():
    global client_ip, client_port
    print("Sending request to HTTP server...")

    # Create a TCP socket for the client
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    # Connect the client socket to the HTTP server
    client_socket.connect((http_server_ip, http_server_port))

    # Construct the HTTP request to the HTTP server
    http_request = f"GET /redirect HTTP/1.1\r\nHost: {http_server_ip}\r\nUser-Agent: Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:92.0) Gecko/20100101 Firefox/92.0\r\n\r\n"

    # Send the request to the HTTP server
    client_socket.sendall(http_request.encode())

    # Add a delay of 2 seconds to give the server time to respond
    time.sleep(2)

    # Receive the response from the HTTP server
    http_response_data = b""
    while True:
        data = client_socket.recv(4096)
        if not data:
            break
        http_response_data += data

    # Close the client socket
    client_socket.close()

    # Handle the response from the HTTP server
    if http_response_data:
        print("Received response from HTTP server.")
        # Create a TCP socket for the client
        client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the client socket to the redirected server
        client_socket.connect((redirected_server_ip, redirected_server_port))

        # Construct the HTTP request to the redirected server
        redirected_request = f"POST /upload HTTP/1.1\r\nHost: {redirected_server_ip}\r\nUser-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36\r\nContent-Type: text/plain\r\nContent-Length: {len(http_response_data)}\r\n\r\n{http_response_data.decode()}"

        # Send the request to the redirected server
        client_socket.sendall(redirected_request.encode())

        # Receive the response from the redirected server
        redirected_response_data = b""
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            redirected_response_data += data

        # Close the client socket
        client_socket.close()

        # Decode the received data as string
        text = redirected_response_data.decode()

        # Print the text to the console
        print("\n printing the text: \n")
        print(text)

    else:
        print("HTTP server did not respond.")

def main():
    send_request()

if __name__ == "__main__":
    main()
