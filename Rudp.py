import random
import struct
import logging
import socket

logging.basicConfig(format = u'[LINE:%(lineno)d]# %(levelname)-8s [%(asctime)s]  %(message)s', level = logging.NOTSET)

SYN = 0b10000000     #instantiez flagurile
ACK = 0b01000000
FIN = 0b00100000
SEQ = 0b00010000
PSH = 0b00001000
NOFLAG = 0b00000000

sock_timeout = 1
receive_size = 2 ** 16 - 1

def random_sequence():
    return random.randint(0, 2 ** 16 - 1)   # [0, 2^16)

def generate_and_pack_header(flags = NOFLAG, ack  = 0, seq = 0): #imi fac headerul pt rudp
    if flags & SYN:        #daca am syn
        seq = random_sequence()
        if flags & ACK:
            ack = (ack + 1) % (2 ** 16)
    else:
        seq = (seq + 1) % (2 ** 16)
        ack = (ack + 1) % (2 ** 16)

    return struct.pack('!H', seq) + struct.pack('!H', ack) + struct.pack('B', flags)

def generate_header_ack(packet):    #header rudp pt confirmarea primiii pachetului ( seq=0, ack = seq + lungime packet) + flag care e ack)
    seq, _, _ = unpack_header(packet)

    return struct.pack("!H", 0) + struct.pack("!H", (seq + len(packet)) % (2 ** 16)) + struct.pack('B', ACK)

def get_header(packet):
    return packet[:5]      #headerul e pe 5 bytes

def get_data(packet):
    return packet[5:].decode()  #info(mesajul) din send_packet

def unpack_header(packet):  #obtin seq ack flags
    header = get_header(packet)
    return struct.unpack('!H', header[0:2])[0], struct.unpack('!H', header[2:4])[0], struct.unpack('B', header[4:5])[0]

def client_handshake(client, server):       #clientul trimite SYN(x = seq random) pana primeste SYN(x = seq random) ACK (x+1)
                                            #dupa ce primeste SYN ACK clientul trimite ACK (seq nr + 1, ack)pana nu mai primeste SYN ACK
    header = generate_and_pack_header(SYN)     #Clientul trimite SYN
    receive_seq = 0
    sent_seq, _, _ = unpack_header(header)

    while True:
        logging.info("Trimit SYN")
        client.sendto(header, server)
        try:
            client.settimeout(sock_timeout)
            received_packet, address = client.recvfrom(receive_size)
            if address == server:
                receive_seq, receive_ack, receive_flags = unpack_header(received_packet)
                if receive_flags & SYN and receive_flags & ACK and receive_ack == sent_seq + 1:
                    logging.info("Am primit SYN si ACK")
                    break
                else:
                    logging.info("Nu am primit SYN")
        except socket.timeout:
            logging.info("Timeout la SYN")


    header = generate_and_pack_header(ACK, receive_seq)     #Trimit ACK
    sent_seq, _, _ = unpack_header(header)

    while True:
        logging.info("Trimit ACK")
        client.sendto(header, server)
        try:
            client.settimeout(sock_timeout)
            received_packet, address = client.recvfrom(receive_size)
            if address == server:
                if received_packet == header:
                    logging.info("Am primit ACK")
                    break;
                else:
                    logging.info("Nu am primit ACK")
        except socket.timeout:
            logging.info("Timeout la ACK pentru client_handshake")

    return sent_seq

def server_handshake(server, client, receive_seq): #3 way handshake din perspectiva serverului
    header = generate_and_pack_header(SYN | ACK | SEQ, receive_seq)
    sent_seq, _, _ = unpack_header(header)

    received = False
    while not received:
        logging.info("Trimit SYN ACK")
        server.sendto(header, client)
        try:
            server.settimeout(sock_timeout)
            received_packet, address = server.recvfrom(receive_size)
            if address == client:
                _, receive_ack, receive_flags = unpack_header(received_packet)
                if receive_flags & ACK and receive_ack == sent_seq + 1:
                    logging.info("Am primit ACK")
                    received = True
                else:
                    logging.info("Nu am primit SYN ACK")
        except socket.timeout:
            logging.info("Timeout SYN ACK pentru server_handshake")

    while True:  # Ca sa stiu ca am primit ack trimit acelasi pachet inapoi
        logging.info("Trimit confirmarea primirii lui ACK")
        server.sendto(received_packet, client)
        try:
            server.settimeout(sock_timeout)
            last_packet, address = server.recvfrom(receive_size)
            if address == client:
                if last_packet != received_packet:
                    logging.info("Confirmarea primirii lui ACK a ajuns")
                    return last_packet
                else:
                    logging.info("Confirmarea primirii lui ACK nu a ajuns")
        except socket.timeout:
             logging.info("Timeout pe confirmarea primirii lui ACK in clien_handshake")

def send_packet(info, seq, sender, receiver): #info = Mesajul de trimis
                                              #de la client trimit catre server packet cu PSH, ACK si SEQ (x+2)
    packet = generate_and_pack_header(PSH | ACK | SEQ, -1, seq) + info.encode()
    sent_seq, _, _ = unpack_header(packet)

    while True:
        logging.info("Trimit pachet cu info: '%s'", info)
        sender.sendto(packet, receiver)
        try:
            sender.settimeout(sock_timeout)
            received_packet, address = sender.recvfrom(receive_size)
            if address == receiver:
                _, received_ack, received_flags = unpack_header(received_packet)
                if received_flags & ACK and received_ack == sent_seq + len(packet):
                    logging.info("Am primit confirmarea pentru pachetul cu info: '%s'", info)
                    break
                else:
                    logging.info("Nu am primit info")
        except socket.timeout:
            logging.info("Timeout la primirea info in send_packet")

    return sent_seq

def receive_packets(last_packet, sock, source): #serverul primeste pachetul si trimite ACK(SEQ + lungime pachet)
                                                # pana primest alt pachet
    while True:
        receive_seq, _, receive_flags = unpack_header(last_packet)
        if receive_flags & FIN:
            logging.info("Am primit FIN")       #vreau sa inchid conexiunea
            break
        else:
            info = get_data(last_packet)
            logging.info('\n')
            logging.info("Am primit pachetul cu info '%s'", info)

            header = generate_header_ack(last_packet)
            while True:
                logging.info("Trimit confirmare pt pachetul cu info '%s'", info)
                sock.sendto(header, source)
                try:
                    sock.settimeout(sock_timeout)
                    received_packet, address = sock.recvfrom(receive_size)
                    if address == source:
                        _, _, receive_flags = unpack_header(received_packet)
                        if received_packet != last_packet and (receive_flags & PSH or receive_flags & FIN):
                            last_packet = received_packet
                            break
                        else:
                            logging.info("Nu am primit confirmare de la client")
                except socket.timeout:
                    logging.info("Timeout nu am primit confirmare in receive_packets")

    receive_fin(received_packet, sock, source)

def send_fin(sequence, sender, receiver):
    '''
    #Cand clientul termina mesajele initiaza inchiderea conexiunii cu un pachet cu flagul FIN
    #Serverul trimite ACK pentru FIN si dupa trimite si el catre client un pachet cu FIN
    #Clientul trimite ACK catre server si se inceie conexiunea
    '''
    header = generate_and_pack_header(FIN | SEQ, -1, sequence)
    sent_seq, _, _ = unpack_header(header)

    while True:                             #Trimit FIN pana primesc ACK
        logging.info("Trimit FIN")
        sender.sendto(header, receiver)
        try:
            sender.settimeout(sock_timeout)
            received_packet, address = sender.recvfrom(receive_size)
            if address == receiver:
                _, receive_ack, receive_flags = unpack_header(received_packet)
                if receive_flags & ACK and receive_ack == sent_seq + 1:
                    logging.info("Am primit ACK")
                    break
                else:
                    logging.info("Nu am primit FIN")
        except socket.timeout:
            logging.info("Timeout nu am primit confirmarea pentru ACK in send_fin")

    while True:                                         #Serverul trimite ACK pentru FIN si dupa trimite
                                                        # si el catre client un pachet cu FIN
        logging.info("Trimit confirmarea primirii ACK")
        sender.sendto(received_packet, receiver)
        try:
            sender.settimeout(sock_timeout)
            last_packet, address = sender.recvfrom(receive_size)
            if address == receiver:
                receive_seq, _, receive_flags = unpack_header(last_packet)
                if last_packet != received_packet and receive_flags & FIN:
                    logging.info("Am primit FIN")
                    break
                else:
                    logging.info("Am primit confirmarea pt ACK")
        except socket.timeout:
            logging.info("Nu am aprimit confirmarea pentru ACK")

    total = 0
    header = generate_and_pack_header(ACK, ack = receive_seq, seq = -1)
    while True:
        logging.info("Trimit ACK")
        sender.sendto(header, receiver)
        try:
            sender.settimeout(sock_timeout)
            received_packet, address = sender.recvfrom(receive_size)
            if address == receiver:
                if received_packet == header:
                    logging.info("A ajuns confirmarea primirii lui ACK")
                    break
                else:
                    logging.info("Nu a ajuns confirmarea primirii lui ACK")
        except socket.timeout:
            logging.info("Timeout la confirmarea primirii lui ACK in send_fin")
            total += 1
            if total == 5:
                break

    logging.info("Conexiunea a fost inchisa cu succes")

def receive_fin(fin_packet, receiver, sender): #Primesc fin, trimit ack si fin, primesc ack
    receive_seq, _, _ = unpack_header(fin_packet)

    header = generate_and_pack_header(ACK, receive_seq)
    while True:
        logging.info("Trimit ACK")                           #Serverul trimite ACK pentru FIN
        receiver.sendto(header, sender)
        try:
            receiver.settimeout(sock_timeout)
            received_packet, address = receiver.recvfrom(receive_size)
            if address == sender:
                if received_packet == header:
                    logging.info("Am primit confirmarea primirii lui ACK")
                    break
                else:
                    logging.info("Nu am primit confirmarea")
        except socket.timeout:
            logging.info("Timeout receive_fin")

    header = generate_and_pack_header(FIN | SEQ, -1, random_sequence())

    while True:
        logging.info("Trimit FIN")                           #Dupa serverul trimite si el FIN
        receiver.sendto(header, sender)
        try:
            receiver.settimeout(sock_timeout)
            last_packet, address = receiver.recvfrom(receive_size)
            if address == sender:
                if received_packet != last_packet:
                    logging.info("Am primit ACK de la sender, confirmarea primiri lui FIN")
                    break
                else:
                    logging.info("Nu am primit FIN in receive_fin")
        except socket.timeout:
            logging.info("Nu a ajuns FIN in receive_fin")

    while True:
        logging.info("Trimit confirmarea primirii lui ACK")     #Pana primeste si el ACK
        receiver.sendto(last_packet, sender)
        try:
            receiver.settimeout(sock_timeout)
            _, _ = receiver.recvfrom(receive_size)
        except socket.timeout:
            logging.info("Inchid conexiunea")
            break


