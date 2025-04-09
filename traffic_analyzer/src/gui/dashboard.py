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
        
        # Protocol Stats Table
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
        self.protocol_table.setHorizontalHeaderLabels(["Protocol", "Count", "Percentage"])
        self.protocol_table.horizontalHeader().setStretchLastSection(True)
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
        self.connections_table.setHorizontalHeaderLabels(["Source", "Destination", "Protocol", "State"])
        self.connections_table.horizontalHeader().setStretchLastSection(True)
        connections_table_layout.addWidget(self.connections_table)
        
        tables_layout.addWidget(connections_table_frame)
        
        layout.addLayout(tables_layout)
        
        self.setLayout(layout)
        
    def update_stat_cards(self, stats):
        """Update the statistics cards with new values."""
        self.total_packets_card.set_value(stats.get('total_packets', 0))
        self.packet_rate_card.set_value(f"{stats.get('packet_rate', 0):.1f}")
        self.data_transfer_card.set_value(self.format_size(stats.get('total_bytes', 0)))
        self.connections_card.set_value(stats.get('active_connections', 0))
        
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
        """Update the protocol and connections tables."""
        # Update protocol table
        self.protocol_table.setRowCount(len(protocol_stats))
        total_packets = sum(protocol_stats.values())
        
        for i, (protocol, count) in enumerate(protocol_stats.items()):
            self.protocol_table.setItem(i, 0, QTableWidgetItem(protocol))
            self.protocol_table.setItem(i, 1, QTableWidgetItem(str(count)))
            percentage = (count / total_packets * 100) if total_packets > 0 else 0
            self.protocol_table.setItem(i, 2, QTableWidgetItem(f"{percentage:.1f}%"))
        
        # Update connections table
        self.connections_table.setRowCount(len(connections))
        for i, conn in enumerate(connections):
            self.connections_table.setItem(i, 0, QTableWidgetItem(conn.get('source', '')))
            self.connections_table.setItem(i, 1, QTableWidgetItem(conn.get('destination', '')))
            self.connections_table.setItem(i, 2, QTableWidgetItem(conn.get('protocol', '')))
            self.connections_table.setItem(i, 3, QTableWidgetItem(conn.get('state', '')))
    
    @staticmethod
    def format_size(size_bytes):
        """Format bytes size to human readable format."""
        for unit in ['B', 'KB', 'MB', 'GB']:
            if size_bytes < 1024:
                return f"{size_bytes:.1f} {unit}"
            size_bytes /= 1024
        return f"{size_bytes:.1f} TB"
    
    def update_dashboard(self, stats):
        """Update all dashboard components with new statistics."""
        try:
            current_time = time.time()
            self.pending_updates += 1
            
            # Only update if enough time has passed since last update
            if current_time - self.last_update_time >= self.update_interval:
                # Update statistics cards
                self.update_stat_cards(stats)
                
                # Update protocol distribution chart
                if 'protocol_stats' in stats:
                    self.update_protocol_chart(stats['protocol_stats'])
                
                # Update timeline chart
                if 'packet_history' in stats:
                    self.update_timeline_chart(stats['packet_history'])
                
                # Update tables
                if 'protocol_stats' in stats and 'connections' in stats:
                    self.update_tables(stats['protocol_stats'], stats['connections'])
                
                # Update capture time
                if 'capture_time' in stats:
                    self.capture_time.setText(f"Capture Time: {stats['capture_time']}")
                
                self.last_update_time = current_time
                self.pending_updates = 0
            
        except Exception as e:
            logging.error(f"Error updating dashboard: {str(e)}") 