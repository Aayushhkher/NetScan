#!/usr/bin/env python3

import sys
import logging
import argparse
from PyQt6.QtWidgets import QApplication
from PyQt6.QtCore import QThread, Qt
from .gui.main_window import MainWindow
from datetime import datetime

def main():
    """Main entry point for the traffic analyzer application."""
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    )
    logger = logging.getLogger(__name__)
    
    try:
        parser = argparse.ArgumentParser(description='NetScan - Advanced Network Traffic Analysis Tool')
        parser.add_argument('--interface', help='Network interface to capture from')
        parser.add_argument('--filter', help='BPF filter for packet capture')
        parser.add_argument('--gui', action='store_true', help='Run in GUI mode')
        args = parser.parse_args()

        if args.gui:
            app = QApplication(sys.argv)
            app.setStyle('Fusion')  # Use Fusion style for a modern look
            
            # Set application-wide stylesheet
            app.setStyleSheet("""
                QMainWindow {
                    background-color: #f8f9fa;
                }
                QTabWidget::pane {
                    border: 1px solid #dee2e6;
                    border-radius: 5px;
                    background-color: white;
                }
                QTabBar::tab {
                    background-color: #e9ecef;
                    border: 1px solid #dee2e6;
                    border-bottom: none;
                    border-top-left-radius: 5px;
                    border-top-right-radius: 5px;
                    padding: 8px 16px;
                    margin-right: 2px;
                }
                QTabBar::tab:selected {
                    background-color: white;
                    border-bottom: none;
                }
                QTableWidget {
                    border: 1px solid #dee2e6;
                    border-radius: 5px;
                    background-color: white;
                }
                QTableWidget::item {
                    padding: 4px;
                }
                QTableWidget::item:selected {
                    background-color: #007bff;
                    color: white;
                }
                QHeaderView::section {
                    background-color: #f8f9fa;
                    border: none;
                    border-right: 1px solid #dee2e6;
                    border-bottom: 1px solid #dee2e6;
                    padding: 8px;
                }
                QPushButton {
                    border-radius: 5px;
                    padding: 8px 16px;
                }
                QLineEdit {
                    border: 1px solid #dee2e6;
                    border-radius: 5px;
                    padding: 8px;
                    background-color: white;
                }
                QComboBox {
                    border: 1px solid #dee2e6;
                    border-radius: 5px;
                    padding: 8px;
                    background-color: white;
                }
            """)

            # Create main window in the main thread
            window = MainWindow()
            window.show()

            # If command line arguments are provided, start capture
            if args.interface:
                window.interface_combo.setCurrentText(args.interface)
            if args.filter:
                window.filter_input.setText(args.filter)
            if args.interface:
                window.start_capture()

            # Run the event loop
            sys.exit(app.exec())
        else:
            # TODO: Implement CLI mode
            print("CLI mode not implemented yet. Use --gui for graphical interface.")
            sys.exit(1)
        
    except Exception as e:
        logger.error(f"Application error: {e}")
        sys.exit(1)

if __name__ == '__main__':
    main() 