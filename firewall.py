#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

import socket
import struct
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext
        self.protocol_dict = {'ICMP':1, 'TCP':6, 'UDP':17, "HTTP":-1}
        self.http_request_type = ["GET", "POST", "PUT", "DROP"]
        self.http_version_number = ["HTTP/1.1", "HTTP/1.0"]
        self.CRLF = "\r\n\r\n"
        # maps (connections) --> [[request_expected_seq, data], [response_expected_seq, data]]
        # request: (src_ip, dst_ip, src_port, dst_port)
        # response: (dst_ip, src_ip, dst_port, src_port) 
        self.http_connections = {} 
        # Load the firewall rules (from rule_filename) here.
        rules_file = open(config['rule'], 'r')
        rules_file_text = rules_file.read()
        if rules_file_text == '':
            self.rules_file_list = []
        else:
            rules_file_text = rules_file_text.split('\n')
            self.rules_file_list = [x for x in rules_file_text if self.determine(x)]

        
        # Load the GeoIP DB ('geoipdb.txt') as well.
        db_file = open('geoipdb.txt', 'r')
        db_file_list = db_file.read()
        db_file_list = db_file_list.split('\n')
        self.db_file_dict = {}
        for i in db_file_list:
            if i != '':
                country = i[-2:]
                if country not in self.db_file_dict:
                    self.db_file_dict[country.upper()] = []
                address_range = i[:-3].split(' ')
                address_range[0] = int('0b' + ''.join([bin(int(x))[2:].zfill(8) for x in address_range[0].split('.')]) , 2)
                address_range[1] = int('0b' + ''.join([bin(int(x))[2:].zfill(8) for x in address_range[1].split('.')]) , 2)  
                self.db_file_dict[country].append(address_range)
        
        # TODO: Also do some initialization if needed.
    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        protocol = pkt[9:10]
        header_length = pkt[0:1] #last 4 bits of 1st byte, need to parse
        
        source_ip_address = socket.inet_ntoa(src_ip)
        destination_ip_address = socket.inet_ntoa(dst_ip)
        # check type of protocol - if not TCP, UDP or ICMP, just pass
        protocol_number, = struct.unpack('!B', protocol)
        if protocol_number not in self.protocol_dict.values() or self.rules_file_list == []:
            self.send_packet(pkt_dir, pkt)
            return
        header_length = self.get_header_length(header_length) 
        # drop packet if header length < 20
        if header_length < 20:
            return
        # data of IPv4 packet
        packet = pkt[header_length:]
        if self.protocol_dict['TCP'] == protocol_number or self.protocol_dict['UDP'] == protocol_number:
            src_port = packet[0:2]
            dst_port = packet[2:4]
            source_port_number = struct.unpack('!H', src_port)[0]
            destination_port_number = struct.unpack('!H', dst_port)[0]
            if pkt_dir == PKT_DIR_INCOMING:
                if self.match_rules(protocol_number, source_ip_address, source_port_number, packet, pkt_dir, pkt[:header_length], header_length):
                    self.send_packet(pkt_dir, pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                if self.match_rules(protocol_number, destination_ip_address, destination_port_number, packet, pkt_dir, pkt[:header_length], header_length):
                    self.send_packet(pkt_dir, pkt)
        elif self.protocol_dict['ICMP'] == protocol_number:
            port = packet[0:1]
            port_number, = struct.unpack('!B', port)
            if pkt_dir == PKT_DIR_INCOMING:
                if self.match_rules(protocol_number, source_ip_address, port_number, packet, pkt_dir, pkt[:header_length], header_length):
                    self.send_packet(pkt_dir, pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                if self.match_rules(protocol_number, destination_ip_address, port_number, packet, pkt_dir, pkt[:header_length], header_length):
                    self.send_packet(pkt_dir, pkt)
              
    def get_header_length(self, header_length):
        b, = struct.unpack('!B', header_length)
        b = bin(b)[2:].zfill(8)
        return int('0b' + b[-4:], 2) * 4
    
    def determine(self, x):
        if len(x) == 0 or x[0] == '%':
            return False
        return True
    
    # helper that sends packet 
    def send_packet(self, pkt_dir, pkt): 
        if pkt_dir == PKT_DIR_INCOMING:
            self.iface_int.send_ip_packet(pkt)
        elif pkt_dir == PKT_DIR_OUTGOING:
            self.iface_ext.send_ip_packet(pkt)
    
    # helper that does binary search on list of lists
    # returns true if val lies within some [min, max] range
    # that is within the list_of_lists
    def binary_search(self, val, list_of_lists, start, end):
        if start > end:
            return False
        mid = (start + end)/2
        lst = list_of_lists[mid]
        if val < lst[0]:
            return self.binary_search(val, list_of_lists, start, mid-1)
        elif val > lst[1]:
            return self.binary_search(val, list_of_lists, mid+1, end)
        else:
            return True

    def calculate_ip_checksum(self, ip_header, header_length):
        total = 0
        i = 0
        while i < header_length-1:
            two_byte_chunk = struct.unpack('!H', ip_header[i:i+2])[0]
            total += two_byte_chunk
            i += 2
        if header_length % 2 != 0:
            ip_header += struct.pack('!B', 0)
            total += struct.unpack('!H', ip_header[i:i+2])[0]
        while (total >> 16) != 0:
            total = (total & 0xFFFF)+(total >> 16)
        #print total 
        #print ~total & 0xFFFF
        return ~total & 0xFFFF

    def calculate_tcp_udp_checksum(self, ip_header, ip_header_length, packet):
        #construct pseudo_header - src address, dst address, zeros, protocol number, tcp length
        pseudo_header = ''
        src_ip = ip_header[12:16] # src ip
        dst_ip = ip_header[16:20] # dst ip
        protocol = ip_header[9:10] # protocol number
        total_length = struct.unpack('!H', ip_header[2:4])[0] - ip_header_length # total length in bytes
        pseudo_header += src_ip
        pseudo_header += dst_ip
        pseudo_header += struct.pack('!B', 0)
        pseudo_header += protocol
        pseudo_header += struct.pack('!H', total_length)
        packet_to_checksum = pseudo_header + packet
        return self.calculate_ip_checksum(packet_to_checksum, total_length + 12)

    def is_valid_ip(self, address):
        parts = address.split('.')
        if len(parts) != 4:
            return False
        for part in parts:
            try:
                if int(part) < 0 or int(part) > 255:
                    return False
            except ValueError:
                return False
        return True

    #returns true if port matches, else false
    def match_port(self, rule_port, external_port):
        #checking for ANY    
        if rule_port.upper() != "ANY":
            #checking for range
            if '-' in rule_port:
                range_rule_port = rule_port.split('-')
                if external_port < int(range_rule_port[0]) or external_port > int(range_rule_port[1]):
                    return False
            #checking for exact match
            elif int(rule_port) != external_port:
                return False
        return True
    
    # return true if address matches, else false
    def match_address(self, rule_address, external_address):
        # checking for ANY
        if rule_address.upper() != "ANY" and  rule_address != "0.0.0.0/0":
            # check for IP Prefix
            if '/' in rule_address:
                # what to do when its a /0 ?
                rule_address_split = rule_address.split('/')
                rule_address_quad = rule_address_split[0].split('.')
                if rule_address_split[1] == "0":
                    return True
                external_address_quad = external_address.split('.')
                rule_address_quad_binary = ''.join([bin(int(x))[2:].zfill(8) for x in rule_address_quad])
                external_address_quad_binary = ''.join([bin(int(x))[2:].zfill(8) for x in external_address_quad])
                rule_address_mask = rule_address_quad_binary[:int(rule_address_split[1])]
                external_address_mask = external_address_quad_binary[:int(rule_address_split[1])]
                if rule_address_mask != external_address_mask:
                    return False
            # check for country code
            elif rule_address.upper() in self.db_file_dict:
                # get list of ip addresses ranges for country
                country_addresses = self.db_file_dict[rule_address.upper()]
                # do binary search on this list
                external_address_val = int('0b' + ''.join([bin(int(x))[2:].zfill(8) for x in external_address.split('.')]) , 2) 
                return self.binary_search(external_address_val, country_addresses, 0, len(country_addresses)-1)
            # check for single IP address
            elif self.is_valid_ip(rule_address) and self.is_valid_ip(external_address):
                if rule_address != external_address:
                    return False
            # check for domain name matching
            else:
                # if no * in front, compare lengths
                rule_address = rule_address.upper()
                external_address = external_address.upper()
                rule_address_split = rule_address.split('.')
                external_address_split = external_address.split('.')
                if rule_address[0] != '*':
                    return rule_address_split == external_address_split
                # if * in front
                if rule_address[0] == '*':
                    rule_address = rule_address[1:]
                if rule_address != '':
                    rule_address_split = rule_address.split('.')
                    if rule_address_split[0] == '':
                        rule_address_split = rule_address_split[1:]
                    if len(rule_address_split) == len(external_address_split):
                        return False
                    if rule_address_split == external_address_split[-len(rule_address_split):]:
                        return True
                    return False
                else:
                    return True
        return True
    
    # helper that returns either true for pass or false for drop, based on protocol/ip/port and DNS rules
    def match_rules(self, protocol, external_ip_address, external_port, packet, pkt_dir, header, header_length):
        # check special case DNS
        is_dns = False
        is_aaaa = False
        q_name = []
        ip_header = header
        name = ''
        if self.protocol_dict['UDP'] == protocol and pkt_dir == PKT_DIR_OUTGOING and external_port == 53:   
            dns_data = packet[8:]
            qd_count = dns_data[4:6]
            if struct.unpack('!H',qd_count)[0] == 1:
                question = dns_data[12:]
                i = 0
                tmp = ''
                hex_zero = struct.pack('!B', 0)
                while question[i] != hex_zero:
                    number = question[i]
                    name += number
                    #print number
                    number = struct.unpack('!B', number)[0]
                    #print number
                    for j in range(1, number+1):
                        tmp += question[i+j]
                        name += question[i+j]
                        #print tmp
                    q_name.append(tmp)
                    tmp = ''
                    i += number + 1
                #increment i by 1 to get QTYPE
                name += hex_zero
                #print name
                i += 1
                qtype = question[i:i+2]
                val = struct.unpack('!H',qtype)[0]
                if val == 1 or val == 28:
                    if val == 28:
                        is_aaaa = True
                    qclass = question[i+2:i+4]
                    if struct.unpack('!H',qclass)[0] == 1:
                        is_dns = True
        
        # walk through all rules
        final_index = -1
        answer = ''
        for rule in range(len(self.rules_file_list)):
            rule_split = self.rules_file_list[rule].split(' ')
            rule_protocol = rule_split[1].upper()
            #check and apply dns rules if rule is type dns
            if rule_protocol == "DNS":
                if is_dns:
                    # name of domain
                    domain = rule_split[2]
                    # if first character is star, then rest of domain 
                    # should match with any address with same suffix
                    #print domain
                    if domain[0] == '*':
                        domain = domain[1:]
                    # if domain was only '*', then it should match
                    # with ALL addresses

                    #################### NOTE ######################
                    # need to add stuff here, since *.foo.com does NOT match foo.com, consult match_address#
                    if domain != '':
                        domain_split = domain.split('.')
                        if domain_split[0] == '':
                            domain_split = domain_split[1:]
                        if domain_split == q_name[-len(domain_split):]:
                            final_index = rule
                            # continue
                    else:
                        final_index = rule
                    
            #check and apply dns rules if rule is udp & port 53
            elif rule_protocol == "UDP" and rule_split[3] == "53":
                if is_dns:
                    # address of domain
                    domain = rule_split[2]
                    match_address_result = self.match_address(domain, external_ip_address)
                    if match_address_result:
                        final_index = rule
                else:
                    match_address_result = self.match_address(rule_split[2], external_ip_address)
                    if match_address_result:
                        final_index = rule
            
            #match to log http
            elif rule_protocol == "HTTP" and self.protocol_dict["TCP"] == protocol:
                #print "http case"
                match_port_result = self.match_port("80", external_port)
                request_host_name = ''
                if not match_port_result:
                    #print "continuing"
                    continue
                # check if HTTP REQUEST, if so, set request_host_name
                tcp_offset = packet[12:13]
                tcp_offset = struct.unpack('!B', tcp_offset)[0]
                tcp_offset = bin(tcp_offset)[2:].zfill(8)[:4]
                tcp_offset = int('0b' + tcp_offset, 2) * 4
                tcp_flags = bin(struct.unpack('!B', packet[13:14])[0])[2:].zfill(8)
                src_ip = ip_header[12:16]
                dst_ip = ip_header[16:20]
                src_port = packet[0:2]
                dst_port = packet[2:4]

                if pkt_dir == PKT_DIR_OUTGOING:
                    if tcp_flags[7] == '1':
                        http_tuple = (src_ip, dst_ip, src_port, dst_port)
                        if http_tuple in self.http_connections:
                            del self.http_connections[http_tuple]
                        return True
                # incoming --> response, outgoing --> request
                seq_no = struct.unpack('!L', packet[4:8])[0]
                #print seq_no
                ack_no = struct.unpack('!L', packet[8:12])[0]
                tcp_data = packet[tcp_offset:]
                if pkt_dir == PKT_DIR_OUTGOING:
                    #print "outgoing"
                    http_tuple = (src_ip, dst_ip, src_port, dst_port)     
                else:
                    #print "incoming"
                    http_tuple = (dst_ip, src_ip, dst_port, src_port)

                if http_tuple not in self.http_connections:
                    #print "syn seq_no " + str(seq_no)
                    #print "new connection"
                    #print http_tuple
                    self.http_connections[http_tuple] = [[seq_no + 1, ''],[-1, ''], [], {"host_name": "", "method": "", "path": "", "version": "", "status_code": "", "object_size": ""}]
                    ### LET SYN PACKET PASS, NOT SURE IF THiS IS RIGHT.
                    return True
                # if its a SYN-ACK, i.e. response, set the EXPECTED REQUEST NUMBER
                # if tcp_flags[3] == '1' and tcp_flags[6] == '1':
                #     if self.http_connections[http_tuple][0][0] == -1 and pkt_dir == PKT_DIR_INCOMING:
                #         self.http_connections[http_tuple][0][0] = ack_no
                #print "expected request: " + str(self.http_connections[http_tuple][0][0])
                #print "expected response: " + str(self.http_connections[http_tuple][1][0])
                if self.http_connections[http_tuple][1][0] == -1 and pkt_dir == PKT_DIR_INCOMING:
                    #print "SYN-ACK"
                    #print "seqno for syn_ack " + str(seq_no)
                    #print "ack_num " + str(ack_no)

                    self.http_connections[http_tuple][1][0] = seq_no + 1
                    #print "expected response: " + str(self.http_connections[http_tuple][1][0])
                    return True
                #### DONT KNOW WHAT TO DO IF SYN PACKETS ARE DROPPED, DOES THE ISN CHANGE??? ###
                # if its the SECOND request, i.e. ACK to the SYN-ACK, set the EXPECTED RESPONSE NUMBER
                # elif self.http_connections[http_tuple][0][0] == -1 and pkt_dir == PKT_DIR_OUTGOING:
                #     #print "ACK to SYN-ACK"
                #     #print "ack_no " + str(ack_no)
                #     self.http_connections[http_tuple][0][0] += 1
                #     return True
                # if its a general request
                elif pkt_dir == PKT_DIR_OUTGOING:
                    #print "general request"
                    #print "expected request: " + str(self.http_connections[http_tuple][0][0])
                    # if self.http_connections[http_tuple][0][0] == -1:
                    #     self.http_connections[http_tuple][0][0] = ack_no
                    if seq_no > self.http_connections[http_tuple][0][0]:
                        return False
                    elif seq_no < self.http_connections[http_tuple][0][0]:
                        return True
                    else:
                        # do request stuff
                        self.http_connections[http_tuple][0][1] += tcp_data
                        if self.CRLF in self.http_connections[http_tuple][0][1]:
                            #print "got the header in request"
                            index_of_CRLF = self.http_connections[http_tuple][0][1].index(self.CRLF)
                            request_header = self.http_connections[http_tuple][0][1][:index_of_CRLF]
                            data = request_header.split('\r\n')
                            while '' in data:
                                data.remove('')
                            #print data
                            current_dict = self.http_connections[http_tuple][3]
                            for field in data:
                                field_split = field.split(' ')
                                if field_split[0].upper() in self.http_request_type:
                                    if current_dict["method"] == "":
                                        current_dict["method"] = field_split[0]
                                    if current_dict["path"] == "":
                                        current_dict["path"] = field_split[1]
                                    if current_dict["version"] == "":
                                        current_dict["version"] = field_split[2]
                                    # if field_split[0] not in self.http_connections[http_tuple][2]:
                                    #     self.http_connections[http_tuple][2].append(field_split[0])
                                    # if field_split[1] not in self.http_connections[http_tuple][2]:
                                    #     self.http_connections[http_tuple][2].append(field_split[1])
                                    # if field_split[2] not in self.http_connections[http_tuple][2]:
                                    #     self.http_connections[http_tuple][2].append(field_split[2])
                                if field_split[0].upper() == "HOST:":
                                    request_host_name = field_split[1]
                                    #print request_host_name
                                    if current_dict["host_name"] == "":
                                        current_dict["host_name"] = request_host_name
                                    # if field_split[1] not in self.http_connections[http_tuple][2]:
                                    #     self.http_connections[http_tuple][2] = [field_split[1]] + self.http_connections[http_tuple][2]
                            if request_host_name == '':
                                request_host_name = external_ip_address
                                if current_dict["host_name"] == "":
                                    current_dict["host_name"] = external_ip_address
                                # if external_ip_address not in self.http_connections[http_tuple][2]:
                                #     self.http_connections[http_tuple][2] = [external_ip_address] + self.http_connections[http_tuple][2]
                        # set the EXPECTED RESPONSE NUMBER to the ack
                        #print ack_no
                        self.http_connections[http_tuple][0][0] += len(tcp_data)
                        
                # if its a general response
                elif pkt_dir == PKT_DIR_INCOMING:
                    #print "general response"
                    #print "expected response: " + str(self.http_connections[http_tuple][1][0])
                    # if self.http_connections[http_tuple][1][0] == -1:
                    #     self.http_connections[http_tuple][1][0] = ack_no
                    #print "seqno " + str(seq_no)
                    #print self.http_connections[http_tuple][1][0]
                    if seq_no > self.http_connections[http_tuple][1][0]:
                        #Fprint "returning"
                        return False
                    elif seq_no < self.http_connections[http_tuple][1][0]:
                        #print "return"
                        return True
                    else:
                        # do response stuff
                        self.http_connections[http_tuple][1][1] += tcp_data
                        if self.CRLF in self.http_connections[http_tuple][1][1]:
                            #print "got the header in response"
                            index_of_CRLF = self.http_connections[http_tuple][1][1].index(self.CRLF)
                            response_header = self.http_connections[http_tuple][1][1][:index_of_CRLF]
                            data = response_header.split('\r\n')
                            while '' in data:
                                data.remove('')
                            #print data
                            current_dict = self.http_connections[http_tuple][3]
                            for field in data:
                                field_split = field.split(' ')
                                if field_split[0].upper() in self.http_version_number:
                                    if current_dict["status_code"] == "":
                                        current_dict["status_code"] = field_split[1]
                                    # if field_split[1] not in self.http_connections[http_tuple][2]:
                                    #     self.http_connections[http_tuple][2].append(field_split[1])
                                if field_split[0].upper() == "CONTENT-LENGTH:":
                                    if current_dict["object_size"] == "":
                                        current_dict["object_size"] = field_split[1]
                                    # if field_split[1] not in self.http_connections[http_tuple][2]:
                                    #     self.http_connections[http_tuple][2].append(field_split[1])

                            # if len(self.http_connections[http_tuple][2]) < 6:
                            if current_dict["object_size"] == "":
                                current_dict["object_size"] = "-1"
                                # if "-1" not in self.http_connections[http_tuple][2]:
                                #     self.http_connections[http_tuple][2].append("-1")
                        # set the EXPECTED REQUEST NUMBER to the ack
                        self.http_connections[http_tuple][1][0] += len(tcp_data)
                # print self.http_connections[http_tuple][2]
                #print self.http_connections[http_tuple][3]
                match_address_result = self.match_address(rule_split[2], request_host_name)
                #print rule_split[2] + " " + request_host_name
                #print match_address_result
                #print match_port_result
                if match_port_result and match_address_result:
                    final_index = rule

            #any rule other than dns, i.e. icmp, tcp, udp
            elif self.protocol_dict[rule_protocol] == protocol:
                #checking external port and checking external address, if they match, this rule correctly applies
                match_port_result = self.match_port(rule_split[3], external_port) 
                match_address_result = self.match_address(rule_split[2], external_ip_address)
                if match_port_result and match_address_result:
                    final_index = rule
        if final_index == -1:
            #print "coming here"
            return True
        else:
            verdict = self.rules_file_list[final_index].split(' ')[0].upper()
            #print verdict
            if verdict == "DENY":
                #print "inside deny"
                if is_dns:
                    #print "inside dns"
                    if is_aaaa:
                        return False
                    udp_header = packet[0:8]
                    dns_data = packet[8:]
                    original_udp_length = struct.unpack('!H', udp_header[4:6])[0]
                    # verifying IP checksum
                    ip_checksum = struct.unpack('!H', ip_header[10:12])[0]
                    ip_header = ip_header[0:10] + struct.pack('!H', 0) + ip_header[12:]
                    calculated_ip_checksum = self.calculate_ip_checksum(ip_header, header_length)
                    if calculated_ip_checksum != ip_checksum:
                        #print "in ip checksum"
                        return False
                    
                    # verifying udp checksum
                    udp_checksum = struct.unpack('!H', udp_header[6:8])[0]
                    udp_header = udp_header[0:6] + struct.pack('!H', 0)
                    calculated_udp_checksum = self.calculate_tcp_udp_checksum(ip_header, header_length, udp_header+dns_data)
                    if calculated_udp_checksum != udp_checksum:
                        #print "in udp checksum"
                        return False
                    # changing QR to 1, TC to 0, not sure about AA, set opcode to 0
                    value = struct.unpack('!B', dns_data[2:3])[0]
                    b = bin(value)[2:].zfill(8)
                    b = '10000' + b[5:6] + '0' + b[7:]
                    b = struct.pack('!B', int('0b' + b, 2))
                    dns_data = dns_data[0:2] + b + dns_data[3:]

                    # changing RCODE to 0
                    value = struct.unpack('!B', dns_data[3:4])[0]
                    b = bin(value)[2:].zfill(8)
                    b = b[0:4] + '0000'
                    b = struct.pack('!B', int('0b' + b, 2))
                    dns_data = dns_data[0:3] + b + dns_data[4:]

                    # changing ANCOUNT to 1
                    val = struct.pack('!H', 1)
                    dns_data = dns_data[0:6] + val + dns_data[8:]

                    # changing NSCOUNT and ARCOUNT to 0
                    dns_data = dns_data[0:8] + struct.pack('!H', 0) + struct.pack('!H', 0) + dns_data[12:]

                    # creating answer section
                    #print len(name)
                    answer += name # set the name
                    #print answer
                    answer += struct.pack('!H', 1) # set the type to 1, A
                    #print answer
                    answer += struct.pack('!H', 1) # set the class to 1, IN
                    #print answer
                    answer += struct.pack('!L', 1) # set the TTL to 1
                    #print answer
                    answer += struct.pack('!H', 4) # set RDLENGTH to 4
                    #print answer
                    answer += struct.pack('!L', int('0b' + ''.join([bin(int(x))[2:].zfill(8) for x in '169.229.49.130'.split('.')]) , 2)) # set RDATA to 169.229.49.130
                    #print answer
                    # add on answer section
                    dns_data = dns_data[0:16 + len(name)] + answer + dns_data[16+len(name)+len(answer):]
                    #print dns_data
                    # change udp_header length
                    new_udp_header_length = 24+len(name)+len(answer) # 12 bytes udp header + (name + 4 bytes) question + answer
                    #udp_header = udp_header[0:4] + struct.pack('!H', original_udp_length+len(answer)) + udp_header[6:]
                    udp_header = udp_header[0:4] + struct.pack('!H', new_udp_header_length) + udp_header[6:]
                    # switch src and dst ip address
                    src_ip = ip_header[12:16]
                    dst_ip = ip_header[16:20]

                    ip_header = ip_header[0:12] + dst_ip + src_ip + ip_header[20:]
                    # switch src and dst ports in udp header
                    src_port = udp_header[0:2]
                    dst_port = udp_header[2:4]
                    udp_header = dst_port + src_port + udp_header[4:]

                    # recalculate udp checksum, add it back to udp header
                    recalculated_udp_checksum = self.calculate_tcp_udp_checksum(ip_header, header_length, udp_header+dns_data)
                    #print recalculated_udp_checksum
                    udp_header = udp_header[0:6] + struct.pack('!H', 0)
                    
                    # change ip total length
                    curr_ip_total_length = struct.unpack('!H', ip_header[2:4])[0]
                    #print curr_ip_total_length
                    #curr_ip_total_length += len(answer)
                    new_ip_header_length = new_udp_header_length + header_length
                    #ip_header = ip_header[0:2] + struct.pack('!H', curr_ip_total_length) + ip_header[4:]
                    ip_header = ip_header[0:2] + struct.pack('!H', new_ip_header_length) + ip_header[4:]
                    #print (curr_ip_total_length + len(answer))
                    # recalculate ip checksum, add it back to ip header
                    recalculated_ip_checksum = self.calculate_ip_checksum(ip_header, header_length)
                    ip_header = ip_header[0:10] + struct.pack('!H', recalculated_ip_checksum) + ip_header[12:]

                    # create complete dns response packet
                    dns_response_packet = ip_header + udp_header + dns_data

                    #send dns response packet
                    self.send_packet(PKT_DIR_INCOMING, dns_response_packet)
                    #print "after send"
                    return False
                else:
                    # deny tcp
                    src_ip = ip_header[12:16]
                    dst_ip = ip_header[16:20]

                    # verifying IP checksum
                    ip_checksum = struct.unpack('!H', ip_header[10:12])[0]
                    ip_header = ip_header[0:10] + struct.pack('!H', 0) + ip_header[12:]
                    calculated_ip_checksum = self.calculate_ip_checksum(ip_header, header_length)
                    if calculated_ip_checksum != ip_checksum:
                        return False
                    
                    # verifying tcp checksum
                    tcp_checksum = struct.unpack('!H', packet[16:18])[0]
                    packet = packet[0:16] + struct.pack('!H', 0) + packet[18:]
                    calculated_tcp_checksum = self.calculate_tcp_udp_checksum(ip_header, header_length, packet)
                    if calculated_tcp_checksum != tcp_checksum:
                        return False

                    # swap dst and src ip
                    ip_header = ip_header[0:12] + dst_ip + src_ip + ip_header[20:]

                    src_port = packet[0:2]
                    dst_port = packet[2:4]

                    # swap dst and src ports
                    packet = dst_port + src_port + packet[4:]

                    # set RST and ACK flags to 1, NOT SURE WHETHER TO CHECK IF ITS A SYN PACKET OR NOT
                    tcp_flags = bin(struct.unpack('!B', packet[13:14])[0])[2:]
                    tcp_flags = '00010100'
                    packet = packet[0:13] + struct.pack('!B', int('0b' + tcp_flags, 2)) + packet[14:]

                    # update the ACK NUMBER
                    seq_no = struct.unpack('!L', packet[4:8])[0]
                    ack_no = struct.unpack('!L', packet[8:12])[0]
                    ack_no = seq_no + 1
                    packet = packet[0:8] + struct.pack('!L', ack_no) + packet[12:]

                    # recalculate tcp checksum, add it back into packet, NOT SURE ABOUT TCP CHECKSUM
                    recalculated_tcp_checksum = self.calculate_tcp_udp_checksum(ip_header, header_length, packet)
                    packet = packet[0:16] + struct.pack('!H', recalculated_tcp_checksum) + packet[18:]

                    # recalculate ip checksum, add it back into header
                    recalculated_ip_checksum = self.calculate_ip_checksum(ip_header, header_length)
                    ip_header = ip_header[0:10] + struct.pack('!H', recalculated_ip_checksum) + ip_header[12:] 

                    # create tcp response packet
                    tcp_response_packet = ip_header + packet

                    # send to internal interface
                    #print "tcp about to send"
                    if pkt_dir == PKT_DIR_INCOMING:
                        pkt_dir = PKT_DIR_OUTGOING
                    else:
                        pkt_dir = PKT_DIR_INCOMING
                    self.send_packet(pkt_dir, tcp_response_packet)
                    #print "tcp sent"
                    return False
            elif verdict == "LOG":
                #print "in log case"
                src_ip = ip_header[12:16]
                dst_ip = ip_header[16:20]
                src_port = packet[0:2]
                dst_port = packet[2:4]
                if pkt_dir == PKT_DIR_OUTGOING:
                    http_tuple = (src_ip, dst_ip, src_port, dst_port)     
                else:
                    http_tuple = (dst_ip, src_ip, dst_port, src_port)
                # check if loggable
                #print "length: " + str(len(self.http_connections[http_tuple][2]))
                #if len(self.http_connections[http_tuple][2]) == 6:
                if "" not in self.http_connections[http_tuple][3].values():
                    #print "logging"
                    f = open("http.log", 'a')
                    # log it
                    #log_result = ' '.join(self.http_connections[http_tuple][2]) + '\n'
                    result_dict = self.http_connections[http_tuple][3]
                    result_str = ""
                    result_str += result_dict["host_name"] + " " + result_dict["method"] + " " + result_dict["path"] + " " + result_dict["version"] + " " + result_dict["status_code"] + " " + result_dict["object_size"] + '\n'
                    f.write(result_str)
                    f.flush()
                    f.close()
                    # clear request/response data from dictionary, NOT SURE IF WE LEAVE EXPECTED SEQUENCE NUMBERS UNCHANGED
                    last_val = result_dict["object_size"]
                    #last_val = self.http_connections[http_tuple][2][-1]
                    self.http_connections[http_tuple][2] = []
                    self.http_connections[http_tuple][0][1] = ''
                    self.http_connections[http_tuple][1][1] = ''
                    self.http_connections[http_tuple][3] = {"host_name": "", "method": "", "path" : "", "version":"", "status_code":"", "object_size": ""}
                    if int(last_val) == -1:
                        del self.http_connections[http_tuple]
                return True
            return verdict == "PASS"

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.