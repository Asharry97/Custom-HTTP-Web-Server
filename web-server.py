
''' All Important Libs & Packages that are required '''
from http.server import SimpleHTTPRequestHandler, HTTPServer, BaseHTTPRequestHandler
from threading import Thread
import ssl
import logging
import time
import multiprocessing
import os
import socket
import sys


'''
Enable Support For Both Ipv4 & Ipv6, This Server wil show Listening on IPv6 Socket But Handles Traffic of IPv4 Socket As well
Depends on 2 Condition 
If
 - Set to ALL IPv6 Address [::], Then Works for (Listens on) All IPv4(0.0.0.0) & IPv6 Address
 - Set to LocalHost IPv6 Address [::1], Then Works for (Listens on) Both IPv4(0.0.0.0) & IPv6 Address
'''


class HTTPServerV6(HTTPServer):
    address_family = socket.AF_INET6  # Enable Address Family IPv6


''' Custom Request Handler '''


class CustomHTTPRequestHandler(BaseHTTPRequestHandler):

    ''' Testing Purpose Func To Enable Pause Between Request Received & Sent back to Client'''
    protocol_version = "HTTP/1.1"  # Support HTTP/1.1
   # server_version = "TimePass/1.1"

    def do_sleep(self):
        sleep_time = 0  # Seconds
        print(f'Sleeping For {sleep_time}')
        time.sleep(sleep_time)

    def set_response_headers(self, content_to_send):
        #self.headers.replace_header('Server', "TimePass/1.1")
        print(self.headers)
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self.send_header('Content-Length', len(content_to_send))

        self.end_headers()

    def do_GET(self):
        content_to_send = f"Received Request By Server: [{self.server.server_address}]\n"
        content_to_send += f"Request Line: \nGET {self.path} {self.protocol_version}\n"
        content_to_send += f"Headers: \n{self.headers}\n"
        content_to_send = content_to_send.encode('utf-8')
        print(content_to_send)
        self.do_sleep()
        self.set_response_headers(content_to_send)
        try:
            self.wfile.write(content_to_send)
        except Exception:
            print("Problem......[Left To Implement Error].......")

    def do_POST(self):
        # Gets Post Data Content-Length
        content_length = int(self.headers['Content-Length'])
        # Gets Post Data Using Content-Length
        post_data = self.rfile.read(content_length)
        content_recieved = f"Received Request By Server: [{self.server.server_address}]\n"
        content_recieved += f"Request Line: POST {self.path} {self.protocol_version}\n"
        content_recieved += f"Headers: \n{self.headers}\n\nBody:\n{post_data.decode('utf-8')}\n"
        content_recieved = content_recieved.encode('utf-8')
        print(content_recieved)
        self.do_sleep()
        self.set_response_headers(content_recieved)
        try:
            self.wfile.write(content_recieved)
        except Exception:
            print("Problem......[Left To Implement Error].......")

    def do_OPTIONS(self):
        self.do_POST()

    def do_ASHISH(self):
        content_to = "ASHISH HERE".encode('utf-8')
        print(content_to)
        self.send_response(200)
        self.end_headers()
        # self.wfile.write()

    do_PUT = do_POST


''' This can only Get Certs IF They are Found inside Dir: certs [Validation Left & also auto generate if not present left]'''


def get_cert_and_key_file():
    cert_file = None
    key_file = None
    if os.path.isdir('certs'):
        file_list = os.listdir('certs')
        for one_file in file_list:
            if one_file.endswith('Server_Cert.pem'):
                cert_file = "certs/" + one_file
                if key_file:
                    break
            if one_file.endswith('Server_Key.pem'):
                key_file = "certs/" + one_file
                if cert_file:
                    break
    if cert_file is None or key_file is None:
        print(
            "Files are Not Present Please Run: [bash generate_certs.sh] Files [Cert_File: " + str(cert_file) + "], [Key_File: " + str(key_file) + "]")
        sys.exit(0)
    return cert_file, key_file


if __name__ == '__main__':

    # Certificate Setup
    cert_file, key_file = get_cert_and_key_file()
    print(f'CertFile:[{cert_file}], KeyFile:[{key_file}]')

    # HTTPS Server
    HTTPS_SOCKET = ('::', 443)
    https_server = HTTPServerV6(HTTPS_SOCKET, CustomHTTPRequestHandler,)
    https_server.socket = ssl.wrap_socket(
        https_server.socket,  keyfile=key_file, certfile=cert_file, server_side=True)
    print("[+] Starting HTTPS Server on Socket: [ " + str(HTTPS_SOCKET) + " ]")
    https_server.serve_forever()

    # HTTP Server
    HTTP_SOCKET = ('::', 80)
    http_server = HTTPServerV6(HTTP_SOCKET, CustomHTTPRequestHandler)
    print("[+] Starting HTTP Server on Socket: [ " + str(HTTP_SOCKET) + " ]")
    # http_server.serve_forever()

    # For Threading [Starting Both HTTP & HTTPS Server]
    Thread(target=https_server.serve_forever).start()  # Start HTTPS Server
    Thread(target=http_server.serve_forever).start()  # Start HTTP Server
