import logging
from PyQt6.QtCore import QObject, pyqtSignal
import os
import time
import json
import datetime
from scapy.all import sniff, IP, TCP, UDP, ICMP, DNS, ARP

class PacketSniffer(QObject):
    """Network packet sniffer using Scapy."""
    
    packet_captured = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.INFO)
        self.is_running = False
        self.current_interface = None
        self.session_packets = []
        self.session_start_time = None
        self.session_file = None
        
        # Define safe protocols
        self.safe_protocols = {
            'TCP', 'UDP', 'ICMP', 'ARP', 'DNS', 'DHCP', 'HTTP', 'HTTPS',
            'SSH', 'NTP', 'SNMP', 'SMB'
        }
        
        # Define suspicious patterns
        self.suspicious_patterns = [
            'portscan',
            'attack',
            'exploit',
            'malware',
            'virus'
        ]
        
        # Create sessions directory
        self.sessions_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), 'sessions')
        os.makedirs(self.sessions_dir, exist_ok=True)
        os.chmod(self.sessions_dir, 0o755)
    
    def get_interfaces(self):
        """Get list of available network interfaces."""
        try:
            from scapy.arch import get_if_list
            interfaces = get_if_list()
            return [iface for iface in interfaces if not iface.startswith(('lo', 'utun'))]
        except Exception as e:
            self.logger.error(f"Error getting interfaces: {e}")
            return []
    
    def start_capture(self, interface=None, filter_str=None):
        """Start capturing packets on the specified interface."""
        try:
            if self.is_running:
                self.logger.warning("Packet capture is already running")
                return
            
            self.is_running = True
            self.current_interface = interface
            self.session_start_time = datetime.datetime.now()
            self.session_packets = []
            
            # Start capture in a separate thread
            from threading import Thread
            self.capture_thread = Thread(
                target=self._capture_packets,
                args=(interface, filter_str),
                daemon=True
            )
            self.capture_thread.start()
            
            self.logger.info(f"Started packet capture on interface: {interface}")
            
        except Exception as e:
            self.is_running = False
            self.error_occurred.emit(f"Error starting capture: {e}")
            self.logger.error(f"Error starting capture: {e}")
    
    def _capture_packets(self, interface, filter_str):
        """Capture packets using Scapy's sniff function."""
        try:
            # Start sniffing
            sniff(
                iface=interface,
                filter=filter_str,
                prn=self._process_packet,
                store=0,
                stop_filter=lambda _: not self.is_running
            )
        except Exception as e:
            self.is_running = False
            self.error_occurred.emit(f"Error in capture thread: {e}")
            self.logger.error(f"Error in capture thread: {e}")
    
    def _process_packet(self, packet):
        """Process a captured packet."""
        try:
            # Basic packet information
            packet_info = {
                'time': time.strftime('%H:%M:%S'),
                'length': len(packet),
                'protocol': 'Unknown',
                'src': 'Unknown',
                'dst': 'Unknown',
                'info': '',
                'bytes': len(packet)
            }
            
            # Extract protocol-specific information
            if IP in packet:
                packet_info.update({
                    'src': packet[IP].src,
                    'dst': packet[IP].dst
                })
                
                if TCP in packet:
                    packet_info.update({
                        'protocol': 'TCP',
                        'info': f"TCP {packet[TCP].sport} → {packet[TCP].dport} [Flags: {packet[TCP].flags}]"
                    })
                elif UDP in packet:
                    packet_info.update({
                        'protocol': 'UDP',
                        'info': f"UDP {packet[UDP].sport} → {packet[UDP].dport}"
                    })
                elif ICMP in packet:
                    packet_info.update({
                        'protocol': 'ICMP',
                        'info': f"ICMP type={packet[ICMP].type} code={packet[ICMP].code}"
                    })
                elif DNS in packet:
                    packet_info.update({
                        'protocol': 'DNS',
                        'info': f"DNS {packet[DNS].qd.qname.decode() if packet[DNS].qd else 'Query'}"
                    })
            elif ARP in packet:
                packet_info.update({
                    'protocol': 'ARP',
                    'src': packet[ARP].psrc,
                    'dst': packet[ARP].pdst,
                    'info': f"ARP {packet[ARP].op} {packet[ARP].psrc} → {packet[ARP].pdst}"
                })
            
            # Add safety analysis
            safety_info = {
                'is_safe': True,
                'warnings': [],
                'risk_level': 'low'
            }
            
            # Check protocol
            if packet_info['protocol'] not in self.safe_protocols:
                safety_info['warnings'].append(f"Uncommon protocol: {packet_info['protocol']}")
                safety_info['is_safe'] = False
                safety_info['risk_level'] = 'medium'
            
            # Check packet info for suspicious patterns
            info = packet_info['info'].lower()
            for pattern in self.suspicious_patterns:
                if pattern in info:
                    safety_info['warnings'].append(f"Suspicious pattern detected: {pattern}")
                    safety_info['is_safe'] = False
                    safety_info['risk_level'] = 'high'
            
            # Store packet in session
            self.session_packets.append({
                'timestamp': time.time(),
                'data': packet_info,
                'safety': safety_info
            })
            
            # Emit packet info
            self.packet_captured.emit({
                'data': packet_info,
                'safety': safety_info
            })
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def stop_capture(self):
        """Stop the packet capture."""
        if not self.is_running:
            return
            
        self.is_running = False
        
        try:
            # Save session data
            if self.session_packets:
                timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
                self.session_file = os.path.join(self.sessions_dir, f'session_{timestamp}.json')
                
                session_data = {
                    'start_time': self.session_start_time.isoformat() if self.session_start_time else None,
                    'end_time': datetime.datetime.now().isoformat(),
                    'interface': self.current_interface,
                    'packets': self.session_packets
                }
                
                with open(self.session_file, 'w') as f:
                    json.dump(session_data, f, indent=2)
                
                self.logger.info(f"Session saved to: {self.session_file}")
            
            # Clear session data
            self.session_packets = []
            self.session_start_time = None
            self.current_interface = None
            
        except Exception as e:
            self.logger.error(f"Error stopping capture: {e}")
        
        self.logger.info("Stopped packet capture") 