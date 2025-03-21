from scapy.all import *
from scapy.layers.http import HTTP
from scapy.layers.dns import DNS
from typing import Dict, Any, Optional
import json
from datetime import datetime

class PacketAnalyzer:
    @staticmethod
    def get_packet_summary(packet):
        """Create a summary of packet information."""
        summary = {
            'timestamp': float(packet.time),
            'source': packet.getlayer(2).src if packet.haslayer(2) else "",
            'destination': packet.getlayer(2).dst if packet.haslayer(2) else "",
            'protocol': packet.lastlayer().name,
            'length': len(packet),
            'source_port': None,
            'dest_port': None,
            'flags': [],
            'additional_info': ""
        }

        # Extract transport layer information
        if packet.haslayer('TCP'):
            summary['source_port'] = packet['TCP'].sport
            summary['dest_port'] = packet['TCP'].dport
            summary['flags'] = PacketAnalyzer._get_tcp_flags(packet)
            summary['additional_info'] = PacketAnalyzer._get_tcp_info(packet)
        elif packet.haslayer('UDP'):
            summary['source_port'] = packet['UDP'].sport
            summary['dest_port'] = packet['UDP'].dport
            summary['additional_info'] = "UDP Datagram"

        # Add application layer information
        if packet.haslayer('DNS'):
            summary['additional_info'] = PacketAnalyzer._get_dns_info(packet)
        elif packet.haslayer('HTTP'):
            summary['additional_info'] = PacketAnalyzer._get_http_info(packet)
        elif packet.haslayer('ICMP'):
            summary['additional_info'] = PacketAnalyzer._get_icmp_info(packet)

        return summary

    @staticmethod
    def _get_tcp_flags(packet):
        """Extract TCP flags from packet."""
        flags = []
        if packet['TCP'].flags.S: flags.append('SYN')
        if packet['TCP'].flags.A: flags.append('ACK')
        if packet['TCP'].flags.F: flags.append('FIN')
        if packet['TCP'].flags.R: flags.append('RST')
        if packet['TCP'].flags.P: flags.append('PSH')
        if packet['TCP'].flags.U: flags.append('URG')
        return flags

    @staticmethod
    def _get_tcp_info(packet):
        """Get TCP-specific information."""
        flags = PacketAnalyzer._get_tcp_flags(packet)
        if flags:
            return f"Flags: {', '.join(flags)}"
        return "TCP Segment"

    @staticmethod
    def _get_dns_info(packet):
        """Get DNS-specific information."""
        dns = packet['DNS']
        if dns.qr == 0:  # Query
            return f"DNS Query: {dns.qd.qname.decode()}"
        else:  # Response
            return f"DNS Response: {dns.qd.qname.decode()}"

    @staticmethod
    def _get_http_info(packet):
        """Get HTTP-specific information."""
        try:
            if packet.haslayer('HTTP Request'):
                return f"HTTP {packet['HTTP Request'].Method.decode()} {packet['HTTP Request'].Path.decode()}"
            elif packet.haslayer('HTTP Response'):
                return f"HTTP Response {packet['HTTP Response'].Status_Code}"
            return "HTTP Packet"
        except:
            return "HTTP Packet"

    @staticmethod
    def _get_icmp_info(packet):
        """Get ICMP-specific information."""
        icmp_types = {
            0: "Echo Reply",
            3: "Destination Unreachable",
            5: "Redirect",
            8: "Echo Request",
            11: "Time Exceeded"
        }
        icmp_type = packet['ICMP'].type
        return f"ICMP {icmp_types.get(icmp_type, f'Type {icmp_type}')}"

    @staticmethod
    def _analyze_http(packet) -> Dict[str, Any]:
        """Analyze HTTP packet details."""
        http_info = {}
        
        try:
            if HTTP in packet:
                # HTTP Request
                if packet.haslayer('HTTPRequest'):
                    http_info['type'] = 'request'
                    http_info['method'] = packet['HTTPRequest'].Method.decode()
                    http_info['path'] = packet['HTTPRequest'].Path.decode()
                    http_info['version'] = packet['HTTPRequest'].Http_Version.decode()
                    
                    # Extract headers
                    headers = {}
                    for field in packet['HTTPRequest'].fields:
                        if field.startswith('Header'):
                            header_name = field.split('_')[1]
                            headers[header_name] = packet['HTTPRequest'].fields[field].decode()
                    http_info['headers'] = headers
                
                # HTTP Response
                elif packet.haslayer('HTTPResponse'):
                    http_info['type'] = 'response'
                    http_info['status_code'] = packet['HTTPResponse'].Status_Code
                    http_info['reason'] = packet['HTTPResponse'].Reason_Phrase.decode()
                    
                    # Extract headers
                    headers = {}
                    for field in packet['HTTPResponse'].fields:
                        if field.startswith('Header'):
                            header_name = field.split('_')[1]
                            headers[header_name] = packet['HTTPResponse'].fields[field].decode()
                    http_info['headers'] = headers
        except Exception as e:
            http_info['error'] = str(e)
        
        return http_info

    @staticmethod
    def _analyze_dns(packet) -> Dict[str, Any]:
        """Analyze DNS packet details."""
        dns_info = {
            'type': 'query' if packet[DNS].qr == 0 else 'response',
            'id': packet[DNS].id,
            'queries': [],
            'answers': []
        }
        
        # Extract queries
        for qname in packet[DNS].qd:
            query = {
                'name': qname.qname.decode(),
                'type': dns_type_to_str(qname.qtype)
            }
            dns_info['queries'].append(query)
        
        # Extract answers for responses
        if dns_info['type'] == 'response':
            for rr in packet[DNS].an:
                answer = {
                    'name': rr.rrname.decode(),
                    'type': dns_type_to_str(rr.type),
                    'ttl': rr.ttl
                }
                
                # Get the appropriate response data based on type
                if rr.type == 1:  # A Record
                    answer['data'] = rr.rdata
                elif rr.type == 5:  # CNAME
                    answer['data'] = rr.cname.decode()
                elif rr.type == 28:  # AAAA Record
                    answer['data'] = rr.rdata
                
                dns_info['answers'].append(answer)
        
        return dns_info

def dns_type_to_str(qtype: int) -> str:
    """Convert DNS query type number to string representation."""
    dns_types = {
        1: 'A',
        2: 'NS',
        5: 'CNAME',
        6: 'SOA',
        12: 'PTR',
        15: 'MX',
        16: 'TXT',
        28: 'AAAA',
        33: 'SRV',
        255: 'ANY'
    }
    return dns_types.get(qtype, str(qtype)) 