import socket
import logging
import Rudp

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)
address = '127.0.0.1'
ip = 10000
server_address = (address, ip)

sequence = Rudp.client_handshake(sock, server_address)

for idx in range(10):
    message = "Mesajul " + str(idx + 1)
    sequence = Rudp.send_packet(message, sequence, sock, server_address)

Rudp.send_fin(sequence, sock, server_address)
