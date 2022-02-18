# nslookup bbc.co.uk 127.0.0.1
# netstat -an
#https://en.wikipedia.org/wiki/Domain_Name_System'
#https://www.iana.org/assignments/dns-parameters/dns-parameters.xhtml

#nslookup
#server 127.0.0.1
#set type=Q
#sky.com

import socket


class DataStream:
  def __init__(self, data):
    self.data = data
    self.pos = 0

  def read_next_field(self, length):
    # Each field is 16 bits (2 bytes) long
    field = self.data[self.pos:self.pos + (length*2)]
    self.pos += (length*2)
    return field




HOST = '127.0.0.1'
PORT = 53

with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
    s.bind((HOST, PORT))

    while True:
      data, address = s.recvfrom(1024)
      stream = DataStream(data)

      Identification = stream.read_next_field(1)
      Flags = stream.read_next_field(1)
      number_of_questions = int.from_bytes(stream.read_next_field(1), "big")
      Answers = stream.read_next_field(1)
      Authority = stream.read_next_field(1)
      Additional = stream.read_next_field(1)
      # QR = stream.read_next_field(1)
      # OPCODE = stream.read_next_field(4)
      # AA = stream.read_next_field(1)
      # TC = stream.read_next_field(1)
      # RD = stream.read_next_field(1)
      # RA = stream.read_next_field(1)
      # Z = stream.read_next_field(3)
      # RC = stream.read_next_field(4)
      # print(number_of_questions)
     
      offset = 12
      for _ in range(number_of_questions):
        parts = []
        while (name_length := data[offset]) != 0:
          offset+=1
          parts.append(data[offset:offset+name_length].decode())
          offset+=name_length
        print(".".join(parts))
        name_ends = offset   # offset is now at the end of the name 0x00
        offset+=1
        type = int.from_bytes(data[offset:offset+2], "big") #15==MX   12=PTR
        offset+=2
        class_code = int.from_bytes(data[offset:offset+2], "big")
        offset+=2
        print(type, class_code)

        response = bytearray()
        
        # Identification
        response.append(data[0])
        response.append(data[1])
        
        # Flags
        #    1 0000 1 0 0 0 000 0000
        response.append(0b10000100)
        response.append(0b00000000)
        
        # number of questions
        response.append(0)
        response.append(0)

        # number of answers
        response.append(0)
        response.append(1)

        # number of authorities
        response.append(0)
        response.append(0)

        # number of additionals
        response.append(0)
        response.append(0)        

        # The answer
        for i in range(12, name_ends+1):
          response.append(data[i])

        # Type
        response.append(data[-4])
        response.append(data[-3])

        # Class
        response.append(data[-2])
        response.append(data[-1])

        # TTL
        response.append(0)
        response.append(0)
        response.append(1)
        response.append(1)

        #RDLENGTH
        response.append(0)
        response.append(4)

        #RDATA
        response.append(1)
        response.append(2)
        response.append(3)
        response.append(4)

        s.sendto(response, address)
