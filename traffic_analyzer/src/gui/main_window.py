from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLabel, QComboBox, QLineEdit, QTableWidget,
                             QTableWidgetItem, QMessageBox, QFileDialog, QTabWidget,
                             QButtonGroup, QFrame, QSizePolicy)
from PyQt6.QtCore import Qt, QTimer, QMetaObject, Q_ARG, pyqtSlot
from PyQt6.QtGui import QAction, QFont
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import pandas as pd
import datetime
from traffic_analyzer.src.core.packet_sniffer import PacketSniffer
from traffic_analyzer.src.utils.packet_analyzer import PacketAnalyzer
from traffic_analyzer.src.gui.dashboard import DashboardWidget
import json
import logging
import time

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("NetScan - Network Traffic Analyzer")
        self.setMinimumSize(1200, 800)
        
        # Configure logging
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        
        # Add file handler for logging
        log_file = 'traffic_analyzer.log'
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
        file_handler.setFormatter(formatter)
        self.logger.addHandler(file_handler)
        
        # Initialize components
        self.packet_sniffer = PacketSniffer()
        self.dashboard = DashboardWidget()
        self.stats = {
            'packet_count': 0,
            'data_transferred': 0,
            'packet_rate': 0,
            'protocol_stats': {},
            'active_connections': set(),
            'start_time': None
        }
        self.packet_list = []
        
        # Setup UI
        self.setup_ui()
        
        # Connect signals
        self.packet_sniffer.packet_captured.connect(self.process_packet)
        self.packet_sniffer.error_occurred.connect(self.handle_error)
        
        # Setup update timer
        self.update_timer = QTimer()
        self.update_timer.timeout.connect(self.update_dashboard)
        self.update_timer.start(1000)  # Update every second
        
        # Refresh interfaces on startup
        self.refresh_interfaces()
        
        self.logger.info("MainWindow initialized")
    
    def setup_ui(self):
        """Initialize the user interface"""
        # Create central widget and main layout
        central_widget = QWidget()
        self.setCentralWidget(central_widget)
        layout = QVBoxLayout(central_widget)
        
        # Control Panel
        control_panel = QHBoxLayout()
        
        # Interface Selection
        interface_label = QLabel("Interface:")
        self.interface_combo = QComboBox()
        self.interface_combo.setMinimumWidth(200)
        self.interface_combo.setStyleSheet("""
            QComboBox {
                padding: 5px;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                background-color: white;
            }
            QComboBox:hover {
                border-color: #adb5bd;
            }
        """)
        
        # Refresh button for interfaces
        refresh_button = QPushButton("⟳")
        refresh_button.setFixedWidth(30)
        refresh_button.clicked.connect(self.refresh_interfaces)
        refresh_button.setStyleSheet("""
            QPushButton {
                background-color: #f8f9fa;
                border: 1px solid #dee2e6;
                border-radius: 4px;
            }
            QPushButton:hover {
                background-color: #e9ecef;
            }
        """)
        
        # Add interface selection to control panel
        control_panel.addWidget(interface_label)
        control_panel.addWidget(self.interface_combo)
        control_panel.addWidget(refresh_button)
        
        # Filter Input
        filter_label = QLabel("Filter:")
        self.filter_input = QLineEdit()
        self.filter_input.setPlaceholderText("Enter BPF filter...")
        self.filter_input.setMinimumWidth(200)
        self.filter_input.setStyleSheet("""
            QLineEdit {
                padding: 5px;
                border: 1px solid #dee2e6;
                border-radius: 4px;
                background-color: white;
            }
            QLineEdit:hover {
                border-color: #adb5bd;
            }
        """)
        
        control_panel.addWidget(filter_label)
        control_panel.addWidget(self.filter_input)
        
        # Filter Buttons
        filter_buttons_layout = QHBoxLayout()
        
        tcp_filter = QPushButton("TCP")
        tcp_filter.clicked.connect(lambda: self.apply_filter("tcp"))
        
        udp_filter = QPushButton("UDP")
        udp_filter.clicked.connect(lambda: self.apply_filter("udp"))
        
        http_filter = QPushButton("HTTP")
        http_filter.clicked.connect(lambda: self.apply_filter("http"))
        
        dns_filter = QPushButton("DNS")
        dns_filter.clicked.connect(lambda: self.apply_filter("dns"))
        
        icmp_filter = QPushButton("ICMP")
        icmp_filter.clicked.connect(lambda: self.apply_filter("icmp"))
        
        clear_filter = QPushButton("Clear")
        clear_filter.clicked.connect(lambda: self.filter_input.clear())
        
        # Add filter buttons to layout
        for button in [tcp_filter, udp_filter, http_filter, dns_filter, icmp_filter, clear_filter]:
            button.setStyleSheet("""
                QPushButton {
                    background-color: #f8f9fa;
                    border: 1px solid #dee2e6;
                    border-radius: 4px;
                    padding: 5px 10px;
                }
                QPushButton:hover {
                    background-color: #e9ecef;
                }
            """)
            filter_buttons_layout.addWidget(button)
        
        # Control Buttons
        self.start_button = QPushButton("Start Capture")
        self.start_button.clicked.connect(self.toggle_capture)
        self.start_button.setStyleSheet("""
            QPushButton {
                background-color: #28a745;
                color: white;
                border: none;
                border-radius: 4px;
                padding: 8px 16px;
            }
            QPushButton:hover {
                background-color: #218838;
            }
        """)
        
        # Add layouts to control panel
        control_panel.addLayout(filter_buttons_layout)
        control_panel.addWidget(self.start_button)
        
        layout.addLayout(control_panel)
        
        # Add Dashboard
        layout.addWidget(self.dashboard)
        
        # Packet Table
        self.packet_table = QTableWidget()
        self.setup_packet_table()
        self.packet_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #dee2e6;
                border: 1px solid #dee2e6;
            }
            QHeaderView::section {
                background-color: #f8f9fa;
                padding: 4px;
                border: 1px solid #dee2e6;
                font-weight: bold;
            }
        """)
        layout.addWidget(self.packet_table)
    
    def setup_packet_table(self):
        """Setup the packet table with columns."""
        self.packet_table.setColumnCount(8)
        self.packet_table.setHorizontalHeaderLabels([
            'Time', 'Protocol', 'Length', 'Source', 'Destination', 'Info', 'Safety', 'Warnings'
        ])
        self.packet_table.horizontalHeader().setStretchLastSection(True)
        
        # Set column widths
        self.packet_table.setColumnWidth(0, 100)  # Time
        self.packet_table.setColumnWidth(1, 100)  # Protocol
        self.packet_table.setColumnWidth(2, 80)   # Length
        self.packet_table.setColumnWidth(3, 150)  # Source
        self.packet_table.setColumnWidth(4, 150)  # Destination
        self.packet_table.setColumnWidth(5, 300)  # Info
        self.packet_table.setColumnWidth(6, 80)   # Safety
        self.packet_table.setColumnWidth(7, 200)  # Warnings
    
    def refresh_interfaces(self):
        """Refresh the list of available network interfaces."""
        current_interface = self.interface_combo.currentText()
        self.interface_combo.clear()
        interfaces = self.packet_sniffer.get_interfaces()
        if interfaces:
            self.interface_combo.addItems(interfaces)
            # Try to restore previous selection
            if current_interface in interfaces:
                self.interface_combo.setCurrentText(current_interface)
            else:
                # Select the first non-loopback interface
                for interface in interfaces:
                    if not interface.startswith('lo'):
                        self.interface_combo.setCurrentText(interface)
                        break
        else:
            QMessageBox.warning(self, "Warning", "No network interfaces found. Please check your network configuration.")
    
    def toggle_capture(self):
        """Toggle packet capture on/off."""
        if not self.packet_sniffer.is_capturing:
            interface = self.interface_combo.currentText()
            filter_text = self.filter_input.text()
            
            try:
                self.packet_sniffer.start_capture(interface, filter_text)
                self.start_button.setText("Stop Capture")
                self.start_button.setStyleSheet("""
                    QPushButton {
                        background-color: #ff4444;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        padding: 8px 16px;
                    }
                    QPushButton:hover {
                        background-color: #c82333;
                    }
                """)
                self.stats['start_time'] = time.time()
                self.stats['packet_count'] = 0
                self.stats['data_transferred'] = 0
                self.stats['protocol_stats'] = {}
                self.stats['active_connections'] = set()
                self.packet_list = []
                self.logger.info("Started packet capture")
            except Exception as e:
                self.logger.error(f"Error toggling capture: {str(e)}")
                QMessageBox.critical(self, "Error", str(e))
        else:
            try:
                self.packet_sniffer.stop_capture()
                self.start_button.setText("Start Capture")
                self.start_button.setStyleSheet("""
                    QPushButton {
                        background-color: #28a745;
                        color: white;
                        border: none;
                        border-radius: 4px;
                        padding: 8px 16px;
                    }
                    QPushButton:hover {
                        background-color: #218838;
                    }
                """)
                self.logger.info("Stopped packet capture")
                session_file = self.packet_sniffer.session_file
                if session_file:
                    self.logger.info(f"Session saved to: {session_file}")
                else:
                    self.logger.info("Capture stopped.")
            except Exception as e:
                self.logger.error(f"Error toggling capture: {str(e)}")
                QMessageBox.critical(self, "Error", str(e))
    
    def process_packet(self, packet_info):
        """Process a captured packet and update the UI."""
        try:
            packet_data = packet_info['data']
            safety_info = packet_info.get('safety', {})
            
            # Update statistics
            self.stats['packet_count'] += 1
            self.stats['data_transferred'] += packet_data.get('bytes', 0)
            
            # Update protocol statistics
            protocol = packet_data.get('protocol', 'Unknown')
            if protocol not in self.stats['protocol_stats']:
                self.stats['protocol_stats'][protocol] = 0
            self.stats['protocol_stats'][protocol] += 1
            
            # Add to packet list
            self.packet_list.append(packet_data)
            
            # Update packet table
            row = self.packet_table.rowCount()
            self.packet_table.insertRow(row)
            
            # Set cell values
            self.packet_table.setItem(row, 0, QTableWidgetItem(packet_data.get('time', '')))
            self.packet_table.setItem(row, 1, QTableWidgetItem(protocol))
            self.packet_table.setItem(row, 2, QTableWidgetItem(str(packet_data.get('length', 0))))
            self.packet_table.setItem(row, 3, QTableWidgetItem(packet_data.get('src', 'Unknown')))
            self.packet_table.setItem(row, 4, QTableWidgetItem(packet_data.get('dst', 'Unknown')))
            self.packet_table.setItem(row, 5, QTableWidgetItem(packet_data.get('info', '')))
            
            # Set safety status
            safety_item = QTableWidgetItem('Safe' if safety_info.get('is_safe', True) else '⚠️ Unsafe')
            safety_item.setForeground(Qt.GlobalColor.green if safety_info.get('is_safe', True) else Qt.GlobalColor.red)
            self.packet_table.setItem(row, 6, safety_item)
            
            # Set warnings
            warnings = safety_info.get('warnings', [])
            warnings_text = '\n'.join(warnings) if warnings else ''
            warnings_item = QTableWidgetItem(warnings_text)
            if warnings:
                warnings_item.setForeground(Qt.GlobalColor.red)
            self.packet_table.setItem(row, 7, warnings_item)
            
            # Scroll to the bottom
            self.packet_table.scrollToBottom()
            
            # Update dashboard
            self.dashboard.update_stats(self.stats)
            
        except Exception as e:
            self.logger.error(f"Error processing packet: {e}")
    
    def update_dashboard(self):
        """Update the dashboard with current statistics."""
        try:
            # Calculate packet rate
            if self.stats['start_time']:
                elapsed = time.time() - self.stats['start_time']
                self.stats['packet_rate'] = self.stats['packet_count'] / elapsed if elapsed > 0 else 0
            
            # Update dashboard
            self.dashboard.update_stat_cards(self.stats)
            self.dashboard.update_protocol_chart(self.stats['protocol_stats'])
            
            # Update timeline with new packets (show last 50 packets for smoother updates)
            if self.packet_list:
                self.dashboard.update_timeline_chart(self.packet_list[-50:])
            
            # Update tables
            connections = [
                {
                    'src': p['src'],
                    'dst': p['dst'],
                    'protocol': p['protocol'],
                    'status': p['flags']
                }
                for p in self.packet_list[-50:]  # Show last 50 connections
            ]
            self.dashboard.update_tables(self.stats['protocol_stats'], connections)
            
            # Update capture time
            if self.stats['start_time']:
                elapsed = int(time.time() - self.stats['start_time'])
                hours = elapsed // 3600
                minutes = (elapsed % 3600) // 60
                seconds = elapsed % 60
                self.dashboard.capture_time.setText(
                    f"Capture Time: {hours:02d}:{minutes:02d}:{seconds:02d}"
                )
            
            # Force update
            self.dashboard.update()
            
        except Exception as e:
            self.logger.error(f"Error updating dashboard: {str(e)}")
    
    def handle_error(self, error_message):
        """Handle errors from the packet sniffer."""
        self.logger.error(f"Packet sniffer error: {error_message}")
        QMessageBox.critical(self, "Error", error_message)
    
    def closeEvent(self, event):
        """Handle application closure."""
        if self.packet_sniffer.is_capturing:
            self.packet_sniffer.stop_capture()
        event.accept()

    def apply_filter(self, filter_text):
        """Apply a capture filter."""
        current_filter = self.filter_input.text().strip()
        if current_filter:
            # Append to existing filter
            self.filter_input.setText(f"{current_filter} and {filter_text}")
        else:
            # Set new filter
            self.filter_input.setText(filter_text)
            
        # If capture is running, restart it with new filter
        if self.packet_sniffer.is_capturing:
            self.toggle_capture()  # Stop
            self.toggle_capture()  # Start with new filter 