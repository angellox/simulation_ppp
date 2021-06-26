import socket
import random
import pickle
import zlib
import struct

flag = escape = "h"

class CHAP:

    def __init__(self, host, port):
        self.host = host
        self.port = port

    def generateId(self):
        value = random.randint(1, 50)
        return value

    def getChallenge(self):
        return 77

    def password(self):
        print(">> password ", end="")
        password = input()

        return password

    def username(self):
        print(">> username ", end="")
        user = input()

        return user

    def generatePPP(self, payload):
        
        formato = bytes(0)
        FCS = b'11111111' + b'00000011' + b'c223'
        header = [bytes.fromhex('7E'), bytes.fromhex('FF'), bytes.fromhex('03'), bytes.fromhex('c223'), 
        bytes.fromhex('7E')]  

        for elemento in payload:
            header.insert(4, elemento) # Insertamos payload en la posición [4]
            FCS = FCS + elemento

        FCS_CRC = zlib.crc32(FCS)
        header.insert(10, struct.pack("!I", FCS_CRC))

        for v in header:
            formato = formato + v

        return formato

    def stuffing(self, mensaje):
        mensaje_stuff = mensaje.replace(flag, escape + flag)

        return mensaje_stuff

    def unstuffing(self, mensaje):
        mensaje_unstuff = mensaje.replace(escape + flag, flag)

        return mensaje_unstuff


    def server_connection(self):
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Bind the socket to the port
        server_address = (self.host, self.port)
        print('\nPPP Authentication Mode - CHAP')
        print('Starting up on {} port {}'.format(*server_address))
        sock.bind(server_address)

        # Listen for incoming connections
        sock.listen(1)

        print('Waiting for a connection...')
        link, client_address = sock.accept()
        
        print('connection from', client_address)

        code = 1 # Código de challenge
        ID = self.generateId() #Generar ID
        challenge = self.getChallenge() # Obtener challenge
        name = self.username() # Escribir el nombre de usuario
        length_challenge = len(str(challenge))
        length_packet = len(str(ID)) + len(str(code)) + len(name) + length_challenge

        payload_h = [struct.pack("B", code), struct.pack("B", ID), struct.pack("!H", length_packet), struct.pack("B", length_challenge), struct.pack("B", challenge), bytes(name, encoding="utf-8")]
        payload_h.reverse()

        ppp_format = self.generatePPP(payload_h)

        link.send(ppp_format)

        data_r = link.recv(1024)
        code_response = struct.unpack("B", data_r[5:6]) #Posición donde está el código
        hash_cliente = struct.unpack("!I", data_r[10:14])
        fin_pack = len(data_r) - 5
        name_cliente = data_r[14:fin_pack].decode('utf-8')

        if data_r:
            if code_response[0] == 2: #Response 
                ID = self.generateId() #Generar ID
                password = self.password()
                value = str(challenge) + password
                hash_servidor = zlib.crc32(value.encode("ascii"))

                if hash_servidor == hash_cliente[0] and name == name_cliente:
                    code_r = 3 #SUCCESS
                    length_p = len(str(ID)) + len(str(code_r))
                    mensaje = "ACK"
                    payload_hh = [struct.pack("B", code_r), struct.pack("B", ID), struct.pack("!H", length_p), bytes(mensaje, encoding="utf-8")]
                    payload_hh.reverse()

                    #print(payload_hh)
                    pf = self.generatePPP(payload_hh)

                    link.send(pf)
                else:
                    code_r = 4 #FAILURE
                    length_p = len(str(ID)) + len(str(code_r))
                    mensaje = "NACK"
                    payload_hh = [struct.pack("B", code_r), struct.pack("B", ID), struct.pack("!H", length_p), bytes(mensaje, encoding="utf-8")]
                    payload_hh.reverse()

                    pf = self.generatePPP(payload_hh)

                    link.send(pf)
        
        msg_packet = link.recv(1024)
        fin = len(msg_packet) - 5
        msg_received = msg_packet[9:fin].decode('utf-8')

        #print(msg_received)

        if msg_received:
            code_msg = struct.unpack("B", msg_packet[5:6]) #Posición donde está el código
            if code_msg[0] == 5: # Tipo mensaje
                msg_unstuff = self.unstuffing(msg_received)
                print("El mensaje es: ", msg_unstuff)

        #finally:
            # Clean up the connection
            # link.close()

    def client_connection(self):
        # Create a TCP/IP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        # Connect the socket to the port where the server is listening
        server_address = (self.host, self.port)
        print('\nPPP Authentication Mode - CHAP')
        print('Connecting to {} port {}'.format(*server_address))
        sock.connect(server_address)

        try:
            #Request
            data = sock.recv(1024)
            
            if data:
                code_response = struct.unpack("B", data[5:6]) #Posición donde está el código
                challenge_value = struct.unpack("B", data[10:11]) #Posición donde está el challenge

                if code_response[0] == 1: # Challenge
                    
                    ID = self.generateId()
                    code = 2
                    name = self.username()
                    password = self.password()
                    length_challenge = len(str(challenge_value))
                    
                    value = str(challenge_value[0]) + password
                    response = zlib.crc32(value.encode("ascii")) # Checksum CRC32
                    length_response = len(str(response))
                    length_packet = len(str(ID)) + len(str(code)) + len(name) + length_response

                    payload_h = [struct.pack("B", code), struct.pack("B", ID), struct.pack("!H", length_packet), struct.pack("B", length_response), struct.pack("!I", response), bytes(name, encoding="utf-8")]
                    payload_h.reverse()

                    ppp_format = self.generatePPP(payload_h)

                    sock.send(ppp_format)

                #print(data)
                #print('received')
            else:
                print('not received')

            data_response = sock.recv(1024)
            codigo = struct.unpack("B", data_response[5:6])

            if data_response:
                if codigo[0] == 3:
                    print('Response: [ACK]')

                    ID = self.generateId()
                    code_msg = 5 # Message
                    print("Escriba su mensaje: ", end="")
                    message = input()
                    msg_stuff = self.stuffing(message)
                    length_msg = len(str(ID)) + len(str(code_msg)) + len(msg_stuff)

                    payload_msg = [struct.pack("B", code_msg), struct.pack("B", ID), struct.pack("!H", length_msg), bytes(msg_stuff, encoding="utf-8")]
                    payload_msg.reverse()

                    ppp_msg = self.generatePPP(payload_msg)

                    sock.send(ppp_msg)

                elif codigo[0] == 4:
                    print('Response: [NACK]')

        finally:
            sock.close()