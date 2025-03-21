import logging
from PyQt6.QtCore import QObject, pyqtSignal
import subprocess
import threading
import os
import signal
import time
import re

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
        
        # Setup basic logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
    
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
            return False
        
        try:
            self.current_interface = interface
            
            # Basic tshark command with more fields
            cmd = [
                'tshark',
                '-i', interface,
                '-p',  # Don't put the interface into promiscuous mode
                '-l',  # Line-buffered mode
                '-n',  # Don't resolve names
                '-T', 'fields',
                '-E', 'separator=,',
                '-e', 'frame.time_epoch',
                '-e', 'ip.src',
                '-e', 'ip.dst',
                '-e', '_ws.col.protocol',
                '-e', 'frame.len',
                '-e', 'tcp.flags',
                '-e', 'udp.port',
                '-e', '_ws.col.info'
            ]
            
            if filter_text:
                cmd.extend(['-f', filter_text])
            
            # Start tshark process
            self.tshark_process = subprocess.Popen(
                cmd,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid  # Create new process group
            )
            
            # Check if process started successfully
            time.sleep(0.1)  # Give process time to start
            if self.tshark_process.poll() is not None:
                error = self.tshark_process.stderr.read()
                raise Exception(f"TShark failed to start: {error}")
            
            # Start capture and error monitoring threads
            self.is_capturing = True
            self.capture_thread = threading.Thread(target=self._capture_packets)
            self.error_thread = threading.Thread(target=self._monitor_errors)
            self.capture_thread.daemon = True
            self.error_thread.daemon = True
            self.capture_thread.start()
            self.error_thread.start()
            
            return True
            
        except Exception as e:
            self.logger.error(f"Error starting capture: {e}")
            self.error_occurred.emit(str(e))
            self.stop_capture()  # Cleanup if startup failed
            return False
    
    def stop_capture(self):
        """Stop capturing packets."""
        if self.is_capturing:
            self.is_capturing = False
            
            if self.tshark_process:
                try:
                    # Try graceful termination first
                    os.killpg(os.getpgid(self.tshark_process.pid), signal.SIGTERM)
                    self.tshark_process.wait(timeout=2)
                except:
                    try:
                        # Force kill if graceful termination fails
                        os.killpg(os.getpgid(self.tshark_process.pid), signal.SIGKILL)
                    except:
                        pass
                finally:
                    self.tshark_process = None
            
            # Wait for threads to finish
            if self.capture_thread:
                self.capture_thread.join(timeout=1)
                self.capture_thread = None
            if self.error_thread:
                self.error_thread.join(timeout=1)
                self.error_thread = None
            
            self.current_interface = None
    
    def _capture_packets(self):
        """Process captured packets."""
        try:
            while self.is_capturing and self.tshark_process:
                line = self.tshark_process.stdout.readline().strip()
                if not line:
                    continue
                
                try:
                    # Parse the comma-separated line
                    fields = line.split(',')
                    if len(fields) >= 8:
                        time_epoch, src_ip, dst_ip, protocol, length, flags, ports, *info = fields
                        
                        # Convert epoch time to readable format
                        try:
                            time_float = float(time_epoch)
                            time_str = time.strftime('%H:%M:%S', time.localtime(time_float))
                        except:
                            time_str = time_epoch
                        
                        # Create packet info
                        packet_info = {
                            'time': time_str,
                            'protocol': protocol.upper() if protocol else 'UNKNOWN',
                            'length': int(length if length else 0),
                            'info': ' '.join(info) if info else protocol.upper() if protocol else 'No Info',
                            'src': src_ip if src_ip else 'Unknown',
                            'dst': dst_ip if dst_ip else 'Unknown',
                            'flags': flags if flags else '',
                            'bytes': int(length if length else 0)
                        }
                        
                        # Only emit if we have valid source or destination
                        if packet_info['src'] != 'Unknown' or packet_info['dst'] != 'Unknown':
                            self.packet_captured.emit(packet_info)
                        
                except Exception as e:
                    self.logger.debug(f"Error processing packet: {e}")
                    continue
                
        except Exception as e:
            if self.is_capturing:  # Only log if we didn't stop intentionally
                self.logger.error(f"Capture thread error: {e}")
                self.error_occurred.emit(str(e))
        finally:
            self.stop_capture() 