import socket
import logging
import Rudp

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)
sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto=socket.IPPROTO_UDP)

address = '127.0.0.1'
ip = 10000
server_address = (address, ip)
sock.bind(server_address)

logging.info("Adresa server: %s. Port: %d", 'localhost', 10000)

while True:
    logging.info('Astept comenzi...')
    data, address = sock.recvfrom(4096) #astept mesajul

    receive_sequence, _, receive_flags = Rudp.unpack_header(data)
    if receive_flags & Rudp.SYN:                                    #daca primeste SYN, atunci vrea sa trimita SYN ACK catre client
        last_packet = Rudp.server_handshake(sock, address, receive_sequence)
        Rudp.receive_packets(last_packet, sock, address)
        break