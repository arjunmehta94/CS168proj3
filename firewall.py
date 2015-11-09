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
        # print self.db_file_dict['AU']
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
            source_port_number = socket.ntohs(struct.unpack('!H', src_port)[0])
            destination_port_number = socket.ntohs(struct.unpack('!H', dst_port)[0])
            if pkt_dir == PKT_DIR_INCOMING:
                if self.match_rules(protocol_number, source_ip_address, source_port_number, packet):
                    self.send_packet(pkt_dir, pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                if self.match_rules(protocol_number, destination_ip_address, destination_port_number, packet):
                    self.send_packet(pkt_dir, pkt)
        elif self.protocol_dict['ICMP'] == protocol_number:
            port = packet[0:1]
            port_number, = struct.unpack('!B', port)
            if pkt_dir == PKT_DIR_INCOMING:
                if self.match_rules(protocol_number, source_ip_address, port_number, packet):
                    self.send_packet(pkt_dir, pkt)
            elif pkt_dir == PKT_DIR_OUTGOING:
                if self.match_rules(protocol_number, destination_ip_address, port_number, packet):
                    self.send_packet(pkt_dir, pkt)
              
    def get_header_length(self, header_length):
        b, = struct.unpack('!B', header_length)
        b = bin(b).zfill(8)
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
            #print "false"
            return False
        mid = (start + end)/2
        lst = list_of_lists[mid]
        if val < lst[0]:
            return self.binary_search(val, list_of_lists, start, mid-1)
        elif val > lst[1]:
            return self.binary_search(val, list_of_lists, mid+1, end)
        else:
            #print"true"
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
        #print "matching address"
        #print "rule_address: " + str(rule_address)
        #print "external_address: " + str(external_address)
        if rule_address.upper() != "ANY" and  rule_address != "0.0.0.0/0":
            # check for IP Prefix
            #print "not ANY"
            if '/' in rule_address:
                # what to do when its a /0 ?
                #print "inside /"
                rule_address_split = rule_address.split('/')
                rule_address_quad = rule_address_split[0].split('.')
                external_address_quad = external_address.split('.')
                rule_address_quad_binary = ''.join([bin(int(x))[2:].zfill(8) for x in rule_address_quad])
                external_address_quad_binary = ''.join([bin(int(x))[2:].zfill(8) for x in external_address_quad])
                rule_address_mask = rule_address_quad_binary[:int(rule_address_split[1])]
                external_address_mask = external_address_quad_binary[:int(rule_address_split[1])]
                if rule_address_mask != external_address_mask:
                    #print "returning false inside /"
                    return False
            # check for country code
            elif rule_address.upper() in self.db_file_dict:
                # get list of ip addresses ranges for country
                #print "in country code case"
                #print rule_address.upper()
                #print "inside country code"
                country_addresses = self.db_file_dict[rule_address.upper()]
                #print country_addresses
                #print country_addresses
                # do binary search on this list
                external_address_val = int('0b' + ''.join([bin(int(x))[2:].zfill(8) for x in external_address.split('.')]) , 2) 
                #print "External address: " + str(external_address)
                #print "External address val: " + str(external_address_val)
                return self.binary_search(external_address_val, country_addresses, 0, len(country_addresses)-1)
            # check for single IP address
            elif rule_address != external_address:
                #print "inside single address"
                return False
        return True
    
    # helper that returns either true for pass or false for drop, based on protocol/ip/port and DNS rules
    def match_rules(self, protocol, external_ip_address, external_port, packet):
        # check special case DNS
        #print "protocol number: " + str(protocol)
        is_dns = False
        q_name = []
        if self.protocol_dict['UDP'] == protocol and external_port == 53:
            dns_data = packet[8:]
            qd_count = dns_data[4:6]
            if socket.ntohs(struct.unpack('!H',qd_count)[0]) == 1:
                question = dns_data[12:]
                i = 0
                tmp = ''
                hex_zero = struct.pack('!B', 0)
                while question[i] != hex_zero:
                    number = question[i]
                    number = struct.unpack('!B', number)
                    for j in range(1, number+1):
                        tmp += question[i+j]
                    q_name.append(tmp)
                    tmp = ''
                    i += number + 1
                #increment i by 1 to get QTYPE
                i += 1
                qtype = question[i:i+2]
                val = socket.ntohs(struct.unpack('!H',qtype)[0])
                if val == 1 or val == 28:
                    qclass = question[i+2:i+4]
                    if socket.ntohs(struct.unpack('!H',qclass)[0]) == 1:
                        is_dns = True
        
        # walk through all rules
        final_index = -1
        for rule in range(len(self.rules_file_list)):
            rule_split = self.rules_file_list[rule].split(' ')
            
            rule_protocol = rule_split[1].upper()
            #print rule_protocol
            #check and apply dns rules if rule is type dns
            if rule_protocol == "DNS":
                if is_dns:
                    # name of domain
                    domain = rule_split[2]
                    # if first character is star, then rest of domain 
                    # should match with any address with same suffix
                    if domain[0] == '*':
                        domain = domain[1:]
                    # if domain was only '*', then it should match
                    # with ALL addresses
                    if domain != '':
                        domain_split = domain.split('.')
                        if domain_split == q_name[-len(domain_split):]:
                            final_index = rule
                    else:
                        final_index = rule
                    
            #check and apply dns rules if rule is udp & port 53
            elif rule_protocol == "UDP" and rule_split[3] == "53":
                if is_dns:
                    # address of domain
                    domain = rule_split[2]
                    

            #any rule other than dns, i.e. icmp, tcp, udp
            elif self.protocol_dict[rule_protocol] == protocol:
                #print "inside protocol match " + str(rule_protocol)
                #checking external port and checking external address, if they match, this rule correctly applies
                match_port_result = self.match_port(rule_split[3], external_port) 
                match_address_result = self.match_address(rule_split[2], external_ip_address)
                #print "match_port_result: " + str(match_port_result)
                #print "match_address_result: " + str(match_address_result)
                if match_port_result and match_address_result:
                    final_index = rule
        if final_index == -1:
            return True
        else:
            #print "default rule: " + str(self.rules_file_list[final_index])
            return self.rules_file_list[final_index].split(' ')[0].upper()  == "PASS"

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
