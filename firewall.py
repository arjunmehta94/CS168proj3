#!/usr/bin/env python

from main import PKT_DIR_INCOMING, PKT_DIR_OUTGOING

# TODO: Feel free to import any Python standard moduless as necessary.
# (http://docs.python.org/2/library/)
# You must NOT use any 3rd-party libraries.
def determine(x):
    if len(x) == 0 or x[0] == '%':
        return False
    return True

class Firewall:
    def __init__(self, config, iface_int, iface_ext):
        self.iface_int = iface_int
        self.iface_ext = iface_ext

        # Load the firewall rules (from rule_filename) here.
        rules_file = open(config['rule'], 'r')
        rules_file_text = rules_file.read()
        rules_file_text = rules_file_text.split('\n')
        rules_file_text = [x for x in rules_file_text if determine(x)]

        
        # Load the GeoIP DB ('geoipdb.txt') as well.
        db_file = open('geoipdb.txt', 'r')
        db_file_list = db_file.read()
        db_file_list = db_file_list.split('\n')
        db_file_dict = {}
        for i in db_file_list:
            if i != '':
                country = i[-2:]
                if country not in db_file_dict:
                    db_file_dict[country] = []
                address_range = i[:-3].split(' ')
                db_file_dict[country].append(address_range)
        
        # TODO: Also do some initialization if needed.

    # @pkt_dir: either PKT_DIR_INCOMING or PKT_DIR_OUTGOING
    # @pkt: the actual data of the IPv4 packet (including IP header)
    def handle_packet(self, pkt_dir, pkt):
        # TODO: Your main firewall code will be here.
        src_ip = pkt[12:16]
        dst_ip = pkt[16:20]
        protocol = pkt[9:10]
        total_length = pkt[2:4]
        header_length = pkt[0:1] #last 4 bits of 1st byte, need to parse

    # TODO: You can add more methods as you want.

# TODO: You may want to add more classes/functions as well.
