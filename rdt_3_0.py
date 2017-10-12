import network_3_0
import argparse
import time
import hashlib
import sys

class Packet:
    ## the number of bytes used to store packet length
    seq_num_S_length = 10
    length_S_length = 10
    ## length of md5 checksum in hex
    checksum_length = 32

    def __init__(self, seq_num, msg_S):
        self.seq_num = seq_num
        self.msg_S = msg_S

    @classmethod
    def from_byte_S(self, byte_S):
        if Packet.corrupt(byte_S):
            raise RuntimeError('Cannot initialize Packet: byte_S is corrupt')
        #extract the fields
        seq_num = int(byte_S[Packet.length_S_length : Packet.length_S_length+Packet.seq_num_S_length])
        msg_S = byte_S[Packet.length_S_length+Packet.seq_num_S_length+Packet.checksum_length :]
        return self(seq_num, msg_S)


    def get_byte_S(self):
        #convert sequence number of a byte field of seq_num_S_length bytes
        seq_num_S = str(self.seq_num).zfill(self.seq_num_S_length)
        #convert length to a byte field of length_S_length bytes
        length_S = str(self.length_S_length + len(seq_num_S) + self.checksum_length + len(self.msg_S)).zfill(self.length_S_length)
        #compute the checksum
        checksum = hashlib.md5((length_S+seq_num_S+self.msg_S).encode('utf-8'))
        checksum_S = checksum.hexdigest()
        #compile into a string
        return length_S + seq_num_S + checksum_S + self.msg_S


    @staticmethod
    def corrupt(byte_S):
        #extract the fields
        length_S = byte_S[0:Packet.length_S_length]
        seq_num_S = byte_S[Packet.length_S_length : Packet.seq_num_S_length+Packet.seq_num_S_length]
        checksum_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length : Packet.seq_num_S_length+Packet.length_S_length+Packet.checksum_length]
        msg_S = byte_S[Packet.seq_num_S_length+Packet.seq_num_S_length+Packet.checksum_length :]

        #compute the checksum locally
        checksum = hashlib.md5(str(length_S+seq_num_S+msg_S).encode('utf-8'))
        computed_checksum_S = checksum.hexdigest()
        #and check if the same
        return checksum_S != computed_checksum_S


class RDT:
    ## latest sequence number used in a packet
    seq_num = 1
    seq_num_rcv = 1
    ## buffer of bytes read from network
    byte_buffer = ''

    def __init__(self, role_S, server_S, port):
        self.network = network_3_0.NetworkLayer(role_S, server_S, port)

    def disconnect(self):
        self.network.disconnect()

    def rdt_3_0_send(self, msg_S):
        #create packet with length, sequence number, checksum, and message
        p = Packet(self.seq_num, msg_S)
        self.network.udt_send(p.get_byte_S())

        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        #keep extracting packets - if reordered, could get more than one
        while True:
            time_holder = time.time() + .05
            while(time.time() < time_holder):
                byte_S = self.network.udt_receive()
                self.byte_buffer += byte_S
                #check if we have received enough bytes
                if(len(self.byte_buffer) >= Packet.length_S_length):
                    length = int(self.byte_buffer[:Packet.length_S_length])
                    #check if we have received the entire "length" of packet
                    if(len(self.byte_buffer) >= length):
                        #check if packet was corrupted
                        if(Packet.corrupt(self.byte_buffer[0:length])):
                            self.byte_buffer = self.byte_buffer[length:]
                            break
                            # Do nothing wait for timeout
                            # self.network.udt_send(p.get_byte_S())
                        else:
                            #if not corrupted
                            rec_pkt = Packet.from_byte_S(self.byte_buffer[0:length])
                            self.byte_buffer = self.byte_buffer[length:]
                            #check if received packet is an ack for the packet we just sent
                            if(rec_pkt.msg_S == 'ACK' and rec_pkt.seq_num >= self.seq_num):
                                self.seq_num = self.seq_num + 1
                                self.byte_buffer = self.byte_buffer[length:]  
                                return
                            else:
                                break
                                # DO nothing wait for timeout
                                # self.network.udt_send(p.get_byte_S())
            self.network.udt_send(p.get_byte_S())

    def rdt_3_0_receive(self):
        #create byte string to hold incomming packets
        ret_S = None
        byte_S = self.network.udt_receive()
        self.byte_buffer += byte_S
        while True:
            #check if we have received enough bytes to extract the length field
            if (len(self.byte_buffer) < Packet.length_S_length):
                return ret_S
            length = int(self.byte_buffer[:Packet.length_S_length])
            #check if we have received "length" bytes
            if (len(self.byte_buffer) < length):
                return ret_S
            #check if packet is corrupt
            if(Packet.corrupt(self.byte_buffer[0:length])):
                nack = Packet(self.seq_num_rcv, 'NACK')
                self.network.udt_send(nack.get_byte_S())
                self.byte_buffer = self.byte_buffer[length:]
            else:
                p = Packet.from_byte_S(self.byte_buffer[0:length])
                #check if packet is the same as the sequence number we are expecting
                if (p.seq_num <= self.seq_num_rcv):
                    ret_S = p.msg_S if (ret_S is None) else ret_S + p.msg_S
                    self.seq_num_rcv = self.seq_num_rcv + 1
                    ack = Packet(p.seq_num, 'ACK')
                    self.network.udt_send(ack.get_byte_S())
                    #Now it is time to listen for .1 seconds for the next packet from sender
                    #if nothing is received in .1 sec, we expire and assume the ACK was received by the sender.
                    end_time = time.time() + .2
                    bb2 = ''
                    while(time.time() < end_time):
                        was_duplicate = False
                        bytes2 = self.network.udt_receive()
                        bb2 += bytes2
                        #restart loop if cannot extract length field
                        try:
                            if (len(bb2) < Packet.length_S_length):
                                continue
                        except ValueError:
                            continue
                        length = int(bb2[:Packet.length_S_length])
                        #restart loop if packet is not "length" long
                        if (len(bb2) < length):
                            continue
                        #if receive corrupt packet, add to the expiration time and NACK
                        if(Packet.corrupt(bb2[0:length])):
                            nack = Packet(self.seq_num_rcv, 'NACK')
                            self.network.udt_send(nack.get_byte_S())
                            bb2 = ''
                            if(was_duplicate):
                                end_time = end_time + .2
                            continue
                        else:
                            p2 = Packet.from_byte_S(bb2[0:length])
                            #If we received the same packet we just ACKed for
                            if (p2.seq_num <= self.seq_num_rcv-1):
                                was_duplicate = True
                                end_time = end_time + .2
                                ack1 = Packet(p2.seq_num, 'ACK')
                                self.network.udt_send(ack1.get_byte_S())
                                bb2 = ''
                            #If we receied the next packet (i.e. the sender moved on from our last ACK)
                            else:
                                nack = Packet(self.seq_num_rcv, 'NACK')
                                self.network.udt_send(nack.get_byte_S())
                                break
                else:
                    nack = Packet(self.seq_num_rcv, 'NACK')
                    self.network.udt_send(nack.get_byte_S())
                self.byte_buffer = self.byte_buffer[length:]

if __name__ == '__main__':
    parser =  argparse.ArgumentParser(description='RDT implementation.')
    parser.add_argument('role', help='Role is either client or server.', choices=['client', 'server'])
    parser.add_argument('server', help='Server.')
    parser.add_argument('port', help='Port.', type=int)
    args = parser.parse_args()

    rdt = RDT(args.role, args.server, args.port)
    if args.role == 'client':
        rdt.rdt_1_0_send('MSG_FROM_CLIENT')
        sleep(2)
        print(rdt.rdt_1_0_receive())
        rdt.disconnect()

    else:
        sleep(1)
        print(rdt.rdt_1_0_receive())
        rdt.rdt_1_0_send('MSG_FROM_SERVER')
        rdt.disconnect()
