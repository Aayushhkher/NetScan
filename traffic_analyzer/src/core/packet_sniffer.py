import logging
from PyQt6.QtCore import QObject, pyqtSignal
import subprocess
import threading
import os
import signal
import time
import re
import json
import datetime

class PacketSniffer(QObject):
    """Simple packet sniffer using tshark."""
    
    packet_captured = pyqtSignal(dict)
    error_occurred = pyqtSignal(str)
    
    def __init__(self):
        super().__init__()
        self.is_capturing = False
        self.capture_thread = None
        self.tshark_process = None
        self.error_thread = None
        self.current_interface = None
        self.session_packets = []
        self.session_start_time = None
        self.session_file = None
        self.packet_buffer = []
        self.buffer_size = 100
        self.last_emit_time = time.time()
        self.emit_interval = 0.1  # Emit packets every 100ms
        
        # Define safe protocols and patterns (reduced set for better performance)
        self.safe_protocols = {
            'TCP', 'UDP', 'ICMP', 'ARP', 'MDNS', 'DNS', 'DHCP', 'HTTP', 'HTTPS',
            'SSH', 'NTP', 'SNMP', 'SMB', 'NBNS', 'LLC', 'BROWSER'
        }
        
        # Define suspicious patterns (reduced set for better performance)
        self.suspicious_patterns = [
            r'portscan',
            r'attack',
            r'exploit',
            r'malware',
            r'virus'
        ]
        
        # Setup basic logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        
        # Create sessions directory if it doesn't exist
        self.sessions_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))), 'sessions')
        os.makedirs(self.sessions_dir, exist_ok=True)
        os.chmod(self.sessions_dir, 0o755)  # Ensure directory is writable
    
    def get_interfaces(self):
        """Get list of available network interfaces."""
        try:
            # Try tshark first for interface list
            result = subprocess.run(['tshark', '-D'], capture_output=True, text=True)
            
            interfaces = []
            for line in result.stdout.splitlines():
                if line.strip():
                    # Extract interface name from line (e.g., "1. en0")
                    match = re.search(r'\d+\.\s+([^\s]+)', line)
                    if match:
                        interface = match.group(1)
                        # Clean up interface name
                        interface = interface.split('(')[0].strip()
                        if interface and not interface.startswith(('any', 'lo', 'utun')):
                            interfaces.append(interface)
            
            return sorted(list(set(interfaces)))  # Remove duplicates and sort
        except Exception as e:
            self.logger.error(f"Error getting interfaces: {e}")
            return []
    
    def _monitor_errors(self):
        """Monitor TShark process stderr for errors."""
        while self.is_capturing and self.tshark_process:
            try:
                error = self.tshark_process.stderr.readline()
                if error:
                    error_str = error.strip()
                    if error_str:
                        # Filter out normal operational messages
                        if "packets captured" in error_str:
                            self.logger.debug(f"TShark info: {error_str}")
                        elif "Capturing on" in error_str:
                            self.logger.info(f"TShark info: {error_str}")
                        elif "BIOCPROMISC" in error_str:
                            # Ignore BIOCPROMISC errors as we're handling it differently
                            self.logger.debug(f"TShark info: {error_str}")
                        else:
                            self.logger.error(f"TShark error: {error_str}")
                            self.error_occurred.emit(f"TShark error: {error_str}")
            except:
                break
    
    def start_capture(self, interface, filter_text=None):
        """Start capturing packets on the specified interface."""
        if self.is_capturing:
            return
            
        self.current_interface = interface
        self.session_start_time = datetime.datetime.now()
        self.session_packets = []
        
        # Create new session file with absolute path
        timestamp = self.session_start_time.strftime('%Y%m%d_%H%M%S')
        self.session_file = os.path.join(self.sessions_dir, f'session_{timestamp}.json')
        
        try:
            # Basic tshark command with more fields
            cmd = [
                'tshark',
                '-i', interface,
                '-T', 'fields',
                '-E', 'separator=,',
                '-e', 'frame.number',
                '-e', 'frame.time',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', '_ws.col.protocol',
                '-e', 'frame.len',
                '-e', '_ws.col.info',
                '-e', 'frame.len',  # Add frame length again to ensure we get it
                '-e', 'ip.len'      # Add IP length to cross-verify
            ]
            
            # Add filter if specified
            if filter_text:
                cmd.extend(['-Y', filter_text])
            
            # Start tshark process
            self.tshark_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                universal_newlines=True
            )
            
            self.is_capturing = True
            
            # Start capture thread
            self.capture_thread = threading.Thread(target=self._capture_packets)
            self.capture_thread.daemon = True
            self.capture_thread.start()
            
            # Start error monitoring thread
            self.error_thread = threading.Thread(target=self._monitor_errors)
            self.error_thread.daemon = True
            self.error_thread.start()
            
            self.logger.info(f"Started packet capture on interface {interface}")
            
        except Exception as e:
            self.logger.error(f"Error starting capture: {e}")
            self.error_occurred.emit(f"Error starting capture: {e}")
            self.stop_capture()
            raise
    
    def stop_capture(self):
        """Stop the packet capture."""
        if not self.is_capturing:
            return

        self.is_capturing = False
        
        if self.tshark_process:
            try:
                if os.name == 'nt':  # Windows
                    os.kill(self.tshark_process.pid, signal.CTRL_C_EVENT)
                else:  # Unix/Linux/MacOS
                    os.kill(self.tshark_process.pid, signal.SIGTERM)
                self.tshark_process.wait(timeout=2)
            except Exception as e:
                self.logger.error(f"Error stopping tshark: {e}")
            finally:
                self.tshark_process = None
        
        # Save session data
        if self.session_file and self.session_packets:
            session_data = {
                'start_time': self.session_start_time.isoformat(),
                'end_time': datetime.datetime.now().isoformat(),
                'interface': self.current_interface,
                'packets': self.session_packets
            }
            try:
                # Ensure the sessions directory exists
                os.makedirs(self.sessions_dir, exist_ok=True)
                
                # Save the session file
                with open(self.session_file, 'w') as f:
                    json.dump(session_data, f, indent=2)
                
                # Set proper permissions
                os.chmod(self.session_file, 0o644)
                
                # Change ownership to current user if running as root
                if os.geteuid() == 0:
                    import pwd
                    current_user = pwd.getpwuid(os.getuid())
                    os.chown(self.session_file, current_user.pw_uid, current_user.pw_gid)
                
                self.logger.info(f"Session saved to {self.session_file}")
            except Exception as e:
                self.logger.error(f"Error saving session: {e}")
        
        # Wait for threads to finish
        if self.capture_thread and self.capture_thread != threading.current_thread():
            self.capture_thread.join(timeout=1)
        if self.error_thread and self.error_thread != threading.current_thread():
            self.error_thread.join(timeout=1)
        
        self.capture_thread = None
        self.error_thread = None
    
    def _capture_packets(self):
        """Capture packets using TShark."""
        try:
            while self.is_capturing:
                line = self.tshark_process.stdout.readline()
                if not line:
                    break
                    
                try:
                    # Parse comma-separated fields
                    fields = line.strip().split(',')
                    if len(fields) >= 9:
                        try:
                            number = int(fields[0]) if fields[0] else 0
                        except ValueError:
                            number = 0
                            
                        # Parse timestamp
                        try:
                            timestamp = fields[1].strip()
                            if timestamp:
                                time_parts = timestamp.split()
                                if len(time_parts) >= 2:
                                    time_str = time_parts[1].split('.')[0]
                                else:
                                    time_str = "00:00:00"
                            else:
                                time_str = "00:00:00"
                        except Exception:
                            time_str = "00:00:00"
                            
                        src_ip = fields[2] if fields[2] else 'Unknown'
                        dst_ip = fields[3] if fields[3] else 'Unknown'
                        protocol = fields[4] if fields[4] else 'Unknown'
                        
                        # Try both frame.len and ip.len for packet size
                        try:
                            frame_len = int(fields[7]) if fields[7] else 0
                            ip_len = int(fields[8]) if fields[8] else 0
                            length = max(frame_len, ip_len)
                        except ValueError:
                            length = 0
                            
                        info = fields[6] if fields[6] else ''
                        
                        # Create packet object
                        packet = {
                            'number': number,
                            'time': time_str,
                            'protocol': protocol,
                            'length': length,
                            'info': info,
                            'src': src_ip,
                            'dst': dst_ip,
                            'flags': '',
                            'bytes': length
                        }
                        
                        # Add to buffer
                        self.packet_buffer.append(packet)
                        
                        # Check if we should emit packets
                        current_time = time.time()
                        if (len(self.packet_buffer) >= self.buffer_size or 
                            current_time - self.last_emit_time >= self.emit_interval):
                            self._emit_buffered_packets()
                            self.last_emit_time = current_time
                        
                except (ValueError, IndexError) as e:
                    self.logger.error(f"Error parsing packet data: {e}")
                    continue
                    
        except Exception as e:
            self.logger.error(f"Error in capture thread: {e}")
            self.error_occurred.emit(f"Error in capture thread: {e}")
        finally:
            if self.is_capturing:
                self.stop_capture()

    def _emit_buffered_packets(self):
        """Emit buffered packets with batch safety analysis."""
        if not self.packet_buffer:
            return
            
        # Process packets in batch
        for packet in self.packet_buffer:
            # Quick safety check
            safety_info = {
                'is_safe': True,
                'warnings': [],
                'risk_level': 'low'
            }
            
            # Check protocol
            protocol = packet.get('protocol', '')
            if protocol not in self.safe_protocols:
                safety_info['warnings'].append(f"Uncommon protocol: {protocol}")
                safety_info['is_safe'] = False
                safety_info['risk_level'] = 'medium'
            
            # Check info for suspicious patterns (only if protocol check failed)
            if not safety_info['is_safe']:
                info = packet.get('info', '').lower()
                for pattern in self.suspicious_patterns:
                    if pattern in info:
                        safety_info['warnings'].append(f"Suspicious pattern: {pattern}")
                        safety_info['risk_level'] = 'high'
            
            # Add to session packets
            self.session_packets.append(packet)
            
            # Emit packet with safety info
            self.packet_captured.emit({
                'data': packet,
                'safety': safety_info
            })
        
        # Clear buffer
        self.packet_buffer.clear()

    def _analyze_packet_safety(self, packet_info):
        """Analyze if a packet is safe or suspicious."""
        safety_info = {
            'is_safe': True,
            'warnings': [],
            'risk_level': 'low'
        }
        
        # Check protocol
        protocol = packet_info.get('protocol', '')
        if protocol not in self.safe_protocols:
            safety_info['warnings'].append(f"Uncommon protocol detected: {protocol}")
            safety_info['is_safe'] = False
            safety_info['risk_level'] = 'medium'
        
        # Check packet info for suspicious patterns
        info = packet_info.get('info', '').lower()
        for pattern in self.suspicious_patterns:
            if pattern in info:
                safety_info['warnings'].append(f"Suspicious pattern detected: {pattern}")
                safety_info['is_safe'] = False
                safety_info['risk_level'] = 'high'
        
        # Check for unusual ports or services
        if protocol in ['TCP', 'UDP']:
            try:
                port = int(packet_info.get('info', '').split()[0])
                if port < 0 or port > 65535:
                    safety_info['warnings'].append(f"Invalid port number: {port}")
                    safety_info['is_safe'] = False
                    safety_info['risk_level'] = 'medium'
                elif port > 1024 and port not in [3306, 5432, 6379, 27017]:  # Common high ports
                    safety_info['warnings'].append(f"Unusual port number: {port}")
                    safety_info['is_safe'] = False
                    safety_info['risk_level'] = 'medium'
            except (ValueError, IndexError):
                pass
        
        return safety_info

    def _process_packet(self, packet_data):
        """Process a captured packet and emit it."""
        try:
            # Process the packet data (existing code)
            packet_info = {
                'timestamp': time.time(),
                'data': packet_data
            }
            
            # Add safety analysis
            safety_info = self._analyze_packet_safety(packet_data)
            packet_info['safety'] = safety_info
            
            # Store packet in session
            self.session_packets.append(packet_info)
            
            # Emit the packet info
            self.packet_captured.emit(packet_info)
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}") 