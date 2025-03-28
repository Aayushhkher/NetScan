from PyQt6.QtWidgets import (QMainWindow, QWidget, QVBoxLayout, QHBoxLayout,
                             QPushButton, QLabel, QComboBox, QLineEdit, QTabWidget,
                             QTableWidget, QTableWidgetItem, QMessageBox, QFileDialog,
                             QFrame, QScrollArea, QSizePolicy)
from PyQt6.QtCore import Qt, QTimer
from PyQt6.QtGui import QColor, QPalette, QFont
import matplotlib
matplotlib.use('Qt5Agg')  # Initialize matplotlib backend
import matplotlib.pyplot as plt
from matplotlib.backends.backend_qt5agg import FigureCanvasQTAgg as FigureCanvas
from matplotlib.figure import Figure
import pandas as pd
from datetime import datetime
import numpy as np
import logging
import time

class StatCard(QFrame):
    """A card widget to display a single statistic."""
    def __init__(self, title, parent=None):
        super().__init__(parent)
        self.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        self.setStyleSheet("""
            QFrame {
                background-color: #f8f9fa;
                border-radius: 8px;
                padding: 10px;
            }
            QLabel {
                color: #495057;
            }
            QLabel#value {
                font-size: 24px;
                font-weight: bold;
                color: #212529;
            }
        """)
        
        layout = QVBoxLayout()
        
        # Title
        title_label = QLabel(title)
        title_label.setStyleSheet("color: #6c757d; font-size: 14px;")
        layout.addWidget(title_label)
        
        # Value
        self.value_label = QLabel("0")
        self.value_label.setObjectName("value")
        layout.addWidget(self.value_label)
        
        self.setLayout(layout)
    
    def set_value(self, value):
        """Update the displayed value."""
        self.value_label.setText(str(value))

class DashboardWidget(QWidget):
    """Widget that displays network traffic statistics and charts."""
    
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setup_ui()
        self.packet_history = []
        self.last_update_time = time.time()
        self.update_interval = 0.1  # Update UI every 100ms
        self.pending_updates = 0
        
    def setup_ui(self):
        """Initialize the user interface."""
        layout = QVBoxLayout()
        
        # Stats Cards Row
        cards_layout = QHBoxLayout()
        
        # Create stat cards
        self.total_packets_card = StatCard("Total Packets")
        self.packet_rate_card = StatCard("Packets/sec")
        self.data_transfer_card = StatCard("Data Transferred")
        self.connections_card = StatCard("Active Connections")
        
        # Add cards to layout with equal spacing
        for card in [self.total_packets_card, self.packet_rate_card, 
                    self.data_transfer_card, self.connections_card]:
            cards_layout.addWidget(card)
            card.setSizePolicy(QSizePolicy.Policy.Expanding, QSizePolicy.Policy.Fixed)
        
        layout.addLayout(cards_layout)
        
        # Capture time
        self.capture_time = QLabel("Capture Time: 00:00:00")
        self.capture_time.setAlignment(Qt.AlignmentFlag.AlignCenter)
        self.capture_time.setStyleSheet("font-size: 14px; color: #6c757d; margin: 10px 0;")
        layout.addWidget(self.capture_time)
        
        # Charts Row
        charts_layout = QHBoxLayout()
        
        # Protocol Distribution Chart
        protocol_frame = QFrame()
        protocol_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        protocol_frame.setStyleSheet("background-color: white; border-radius: 8px;")
        protocol_layout = QVBoxLayout(protocol_frame)
        
        self.protocol_fig = Figure(figsize=(6, 4), dpi=100)
        self.protocol_ax = self.protocol_fig.add_subplot(111)
        self.protocol_canvas = FigureCanvas(self.protocol_fig)
        protocol_layout.addWidget(self.protocol_canvas)
        
        # Add title label
        protocol_title = QLabel("Protocol Distribution")
        protocol_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        protocol_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #495057;")
        protocol_layout.insertWidget(0, protocol_title)
        
        charts_layout.addWidget(protocol_frame)
        
        # Timeline Chart
        timeline_frame = QFrame()
        timeline_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        timeline_frame.setStyleSheet("background-color: white; border-radius: 8px;")
        timeline_layout = QVBoxLayout(timeline_frame)
        
        self.timeline_fig = Figure(figsize=(6, 4), dpi=100)
        self.timeline_ax = self.timeline_fig.add_subplot(111)
        self.timeline_canvas = FigureCanvas(self.timeline_fig)
        timeline_layout.addWidget(self.timeline_canvas)
        
        # Add title label
        timeline_title = QLabel("Network Activity")
        timeline_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        timeline_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #495057;")
        timeline_layout.insertWidget(0, timeline_title)
        
        charts_layout.addWidget(timeline_frame)
        
        layout.addLayout(charts_layout)
        
        # Tables Row
        tables_layout = QHBoxLayout()
        
        # Protocol Table
        protocol_table_frame = QFrame()
        protocol_table_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        protocol_table_frame.setStyleSheet("background-color: white; border-radius: 8px;")
        protocol_table_layout = QVBoxLayout(protocol_table_frame)
        
        protocol_table_title = QLabel("Protocol Statistics")
        protocol_table_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        protocol_table_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #495057;")
        protocol_table_layout.addWidget(protocol_table_title)
        
        self.protocol_table = QTableWidget()
        self.protocol_table.setColumnCount(3)
        self.protocol_table.setHorizontalHeaderLabels(["Protocol", "Count", "Size"])
        self.protocol_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #dee2e6;
                border: none;
            }
            QHeaderView::section {
                background-color: #f8f9fa;
                padding: 4px;
                border: 1px solid #dee2e6;
                font-weight: bold;
            }
        """)
        protocol_table_layout.addWidget(self.protocol_table)
        tables_layout.addWidget(protocol_table_frame)
        
        # Connections Table
        connections_table_frame = QFrame()
        connections_table_frame.setFrameStyle(QFrame.Shape.StyledPanel | QFrame.Shadow.Raised)
        connections_table_frame.setStyleSheet("background-color: white; border-radius: 8px;")
        connections_table_layout = QVBoxLayout(connections_table_frame)
        
        connections_table_title = QLabel("Active Connections")
        connections_table_title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        connections_table_title.setStyleSheet("font-size: 16px; font-weight: bold; color: #495057;")
        connections_table_layout.addWidget(connections_table_title)
        
        self.connections_table = QTableWidget()
        self.connections_table.setColumnCount(4)
        self.connections_table.setHorizontalHeaderLabels(["Source", "Destination", "Protocol", "Status"])
        self.connections_table.setStyleSheet("""
            QTableWidget {
                gridline-color: #dee2e6;
                border: none;
            }
            QHeaderView::section {
                background-color: #f8f9fa;
                padding: 4px;
                border: 1px solid #dee2e6;
                font-weight: bold;
            }
        """)
        connections_table_layout.addWidget(self.connections_table)
        tables_layout.addWidget(connections_table_frame)
        
        layout.addLayout(tables_layout)
        
        self.setLayout(layout)
        
        # Set up color scheme for protocol chart
        self.protocol_colors = {
            'TCP': '#007bff',
            'UDP': '#28a745',
            'HTTP': '#17a2b8',
            'DNS': '#ffc107',
            'ICMP': '#dc3545',
            'TLS': '#6610f2',
            'Other': '#6c757d'
        }
        
        # Initialize empty charts
        self.update_protocol_chart({})
        self.update_timeline_chart([])
        
    def update_stat_cards(self, stats):
        """Update the stat cards with new values"""
        try:
            self.total_packets_card.set_value(stats.get('packet_count', 0))
            self.packet_rate_card.set_value(f"{stats.get('packet_rate', 0):.2f}")
            self.data_transfer_card.set_value(self.format_size(stats.get('data_transferred', 0)))
            self.connections_card.set_value(len(stats.get('active_connections', set())))
        except Exception as e:
            print(f"Error updating stat cards: {str(e)}")
    
    def update_protocol_chart(self, protocol_stats):
        """Update the protocol distribution pie chart"""
        try:
            self.protocol_ax.clear()
            
            if not protocol_stats:
                self.protocol_ax.text(0.5, 0.5, 'No data', ha='center', va='center')
            else:
                # Prepare data
                protocols = list(protocol_stats.keys())
                counts = list(protocol_stats.values())
                
                # Create pie chart with optimized settings
                self.protocol_ax.pie(counts, labels=protocols, autopct='%1.1f%%', 
                                   textprops={'fontsize': 8},  # Smaller font size
                                   pctdistance=0.85)  # Move percentage labels closer to center
                self.protocol_ax.set_title('Protocol Distribution', fontsize=10)
            
            # Use tight layout with reduced padding
            self.protocol_fig.tight_layout(pad=0.5)
            self.protocol_canvas.draw_idle()  # Use draw_idle for better performance
            
        except Exception as e:
            logging.error(f"Error updating protocol chart: {str(e)}")
    
    def update_timeline_chart(self, packet_data):
        """Update the packet rate timeline chart"""
        try:
            self.timeline_ax.clear()
            
            if not packet_data:
                self.timeline_ax.text(0.5, 0.5, 'No data', ha='center', va='center')
            else:
                # Prepare data
                times = []
                bytes_transferred = []
                total_bytes = 0
                
                # Process only the last 100 packets for better performance
                for p in packet_data[-100:]:
                    try:
                        time_str = p.get('time', '00:00:00')
                        bytes_val = p.get('length', 0)
                        total_bytes += bytes_val
                        times.append(time_str)
                        bytes_transferred.append(total_bytes)
                    except Exception as e:
                        logging.error(f"Error processing packet for timeline: {e}")
                        continue
                
                # Create line plot with optimized settings
                if times and bytes_transferred:
                    self.timeline_ax.plot(range(len(times)), bytes_transferred, 
                                       '-b', linewidth=1, marker='o', markersize=2)
                    
                    # Set x-axis labels with reduced number of ticks
                    num_ticks = min(5, len(times))
                    if num_ticks > 0:
                        tick_positions = np.linspace(0, len(times) - 1, num_ticks, dtype=int)
                        self.timeline_ax.set_xticks(tick_positions)
                        self.timeline_ax.set_xticklabels([times[i] for i in tick_positions], 
                                                       rotation=45, fontsize=8)
                    
                    self.timeline_ax.set_title('Network Activity Timeline', fontsize=10)
                    self.timeline_ax.set_xlabel('Time', fontsize=8)
                    self.timeline_ax.set_ylabel('Total Bytes Transferred', fontsize=8)
                    self.timeline_ax.grid(True, linestyle='--', alpha=0.3)
                    
                    # Format y-axis with reduced precision
                    self.timeline_ax.yaxis.set_major_formatter(
                        plt.FuncFormatter(lambda x, p: self.format_size(x))
                    )
                    
                    # Auto-scale with reduced padding
                    y_min, y_max = self.timeline_ax.get_ylim()
                    padding = (y_max - y_min) * 0.05
                    self.timeline_ax.set_ylim(y_min - padding, y_max + padding)
            
            # Use tight layout with reduced padding
            self.timeline_fig.tight_layout(pad=0.5)
            self.timeline_canvas.draw_idle()  # Use draw_idle for better performance
            
        except Exception as e:
            logging.error(f"Error updating timeline chart: {e}")
    
    def update_tables(self, protocol_stats, connections):
        """Update the protocol and connections tables"""
        try:
            # Update protocol table
            self.protocol_table.setRowCount(len(protocol_stats))
            for i, (protocol, count) in enumerate(protocol_stats.items()):
                self.protocol_table.setItem(i, 0, QTableWidgetItem(protocol))
                self.protocol_table.setItem(i, 1, QTableWidgetItem(str(count)))
                self.protocol_table.setItem(i, 2, QTableWidgetItem(self.format_size(count)))
            
            # Update connections table
            self.connections_table.setRowCount(len(connections))
            for i, conn in enumerate(connections):
                self.connections_table.setItem(i, 0, QTableWidgetItem(conn['src']))
                self.connections_table.setItem(i, 1, QTableWidgetItem(conn['dst']))
                self.connections_table.setItem(i, 2, QTableWidgetItem(conn['protocol']))
                self.connections_table.setItem(i, 3, QTableWidgetItem(conn['status']))
        except Exception as e:
            print(f"Error updating tables: {str(e)}")
    
    @staticmethod
    def format_size(size_bytes):
        """Format size in bytes to human readable string"""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.2f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.2f} TB"

    def update_tcp_flags_chart(self, flags_stats):
        """Update the TCP flags distribution chart."""
        # This method can be implemented if needed
        pass
        
    def update_ports_chart(self, port_stats):
        """Update the port distribution chart."""
        # This method can be implemented if needed
        pass

    def update_dashboard(self, stats):
        """Update dashboard with current statistics."""
        try:
            current_time = time.time()
            
            # Always update stat cards as they're lightweight
            self.total_packets_card.set_value(stats.get('packet_count', 0))
            self.packet_rate_card.set_value(f"{stats.get('packet_rate', 0):.2f}")
            self.data_transfer_card.set_value(self.format_size(stats.get('data_transferred', 0)))
            self.connections_card.set_value(len(stats.get('active_connections', set())))
            
            # Increment pending updates counter
            self.pending_updates += 1
            
            # Check if we should update charts and tables
            if current_time - self.last_update_time >= self.update_interval:
                # Update protocol distribution chart
                self.update_protocol_chart(stats.get('protocol_stats', {}))
                
                # Update network activity timeline
                self.update_timeline_chart(stats.get('timeline_data', []))
                
                # Update tables
                connections = [
                    {
                        'src': p['src'],
                        'dst': p['dst'],
                        'protocol': p['protocol'],
                        'status': p['flags']
                    }
                    for p in stats.get('timeline_data', [])[-50:]  # Show last 50 connections
                ]
                self.update_tables(stats.get('protocol_stats', {}), connections)
                
                self.last_update_time = current_time
                self.pending_updates = 0
            
            # Force update only if we have enough pending updates
            if self.pending_updates >= 10:
                self.update()
                self.pending_updates = 0
            
        except Exception as e:
            logging.error(f"Error updating dashboard: {str(e)}")

    def update_timeline(self, timeline_data):
        """Update network activity timeline."""
        try:
            # Clear previous data
            self.timeline_ax.clear()
            
            if not timeline_data:
                self.timeline_ax.text(0.5, 0.5, 'No data', ha='center', va='center')
            else:
                # Prepare data
                times = [d['time'] for d in timeline_data]
                bytes_transferred = [d['bytes'] for d in timeline_data]
                
                # Create line plot
                self.timeline_ax.plot(times, bytes_transferred, '-o')
                self.timeline_ax.set_title('Network Activity Timeline')
                self.timeline_ax.set_xlabel('Time')
                self.timeline_ax.set_ylabel('Bytes Transferred')
                self.timeline_ax.grid(True)
                
                # Rotate x-axis labels for better readability
                plt.setp(self.timeline_ax.get_xticklabels(), rotation=45)
            
            self.timeline_fig.tight_layout()
            self.timeline_canvas.draw()
        except Exception as e:
            logging.error(f"Error updating timeline: {str(e)}") 