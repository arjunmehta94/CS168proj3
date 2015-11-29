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
        self.protocol_dict = {'ICMP':1, 'TCP':6, 'UDP':17}
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
                if self.match_rules(protocol_number, source_ip_address, source_port_number, packet, pkt_dir, pkt[:header_length]):
                    self.send_packet(pkt_dir, pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                if self.match_rules(protocol_number, destination_ip_address, destination_port_number, packet, pkt_dir, pkt[:header_length]):
                    self.send_packet(pkt_dir, pkt)
        elif self.protocol_dict['ICMP'] == protocol_number:
            port = packet[0:1]
            port_number, = struct.unpack('!B', port)
            if pkt_dir == PKT_DIR_INCOMING:
                if self.match_rules(protocol_number, source_ip_address, port_number, packet, pkt_dir, pkt[:header_length]):
                    self.send_packet(pkt_dir, pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                if self.match_rules(protocol_number, destination_ip_address, port_number, packet, pkt_dir, pkt[:header_length]):
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
        while i != header_length:
            two_byte_chunk = struct.unpack('!H', ip_header[i:i+2])[0]
            total += two_byte_chunk
            i += 2
        if i != header_length:
            total += struct.unpack('!H', ip_header[i:i+1])[0]
        while (total >> 16) != 0:
            total = (total & 0xFFFF)+(total >> 16)
        return ~total

    def calculate_tcp_checksum(self, ip_header, ip_header_length, tcp_packet):
        #construct pseudo_header - src address, dst address, zeros, protocol number, tcp length
        pseudo_header = ''
        src_ip = ip_header[12:16] # src ip
        dst_ip = ip_header[16:20] # dst ip
        protocol = ip_header[9:10] # protocol number
        tcp_total_length = struct.unpack('!H', ip_header[2:4])[0] - ip_header_length # total length in bytes
        pseudo_header += src_ip
        pseudo_header += dst_ip
        pseudo_header += struct.pack('!B', 0)
        pseudo_header += protocol
        pseudo_header += struct.pack('!H', tcp_total_length)
        tcp_packet_to_checksum = pseudo_header + tcp_packet
        return self.calculate_ip_checksum(tcp_packet_to_checksum, tcp_total_length + 12)



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
            elif rule_address != external_address:
                return False
        return True
    
    # helper that returns either true for pass or false for drop, based on protocol/ip/port and DNS rules
    def match_rules(self, protocol, external_ip_address, external_port, packet, pkt_dir, header):
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
            #any rule other than dns, i.e. icmp, tcp, udp
            elif self.protocol_dict[rule_protocol] == protocol:
                #checking external port and checking external address, if they match, this rule correctly applies
                match_port_result = self.match_port(rule_split[3], external_port) 
                match_address_result = self.match_address(rule_split[2], external_ip_address)
                if match_port_result and match_address_result:
                    final_index = rule
        if final_index == -1:
            return True
        else:
            verdict = self.rules_file_list[final_index].split(' ')[0].upper()
            if verdict == "DENY":
                #print "inside deny"
                if is_dns:
                    #print "inside dns"
                    if is_aaaa:
                        return False
                    udp_header = packet[0:8]
                    dns_data = packet[8:]

                    # set ip header destination to address
                    # ip_header = ip_header[0:16] + socket.inet_aton("169.229.49.130") + ip_header[20:]

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
                    answer += name # set the name
                    answer += struct.pack('!H', 1) # set the type to 1, A
                    answer += struct.pack('!H', 1) # set the class to 1, IN
                    answer += struct.pack('!L', 1) # set the TTL to 1
                    answer += struct.pack('!H', 4) # set RDLENGTH to 4
                    answer += struct.pack('!L', int('0b' + ''.join([bin(int(x))[2:].zfill(8) for x in '169.229.49.130'.split('.')]) , 2)) # set RDATA to 169.229.49.130

                    # add on answer section
                    dns_data = dns_data[0:17 + len(name)] + answer + dns_data[17+len(name)+len(answer):]

                    # change udp_header length
                    new_udp_header_length = 16+len(name)+len(answer)
                    udp_header = udp_header[0:4] + struct.pack('!H', new_udp_header_length) + udp_header[6:]

                    # recalculate udp checksum

                    # change ip total length
                    curr_ip_total_length = struct.unpack('!H', ip_header[2:4])[0]
                    ip_header = ip_header[0:2] + struct.pack('!H', curr_ip_total_length + len(answer)) + ip_header[4:]

                    # recalculate ip checksum


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

                    # swap dst and src ip
                    ip_header = ip_header[0:12] + dst_ip + src_ip + ip_header[20:]

                    src_port = packet[0:2]
                    dst_port = packet[2:4]

                    # swap dst and src ports
                    packet = dst_port + src_port + packet[4:]

                    # set RST flag to 1
                    tcp_flags = struct.unpack('!B', packet[13:14])[0]
                    tcp_flags = tcp_flags[0:5] + '1' + tcp_flags[6:]
                    packet = packet[0:13] + struct.pack('!B', int('0b' + tcp_flags, 2)) + packet[14:]

                    # calculate checksum

            return verdict == "PASS"

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.