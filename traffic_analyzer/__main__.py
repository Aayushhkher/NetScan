#!/usr/bin/env python3
"""
Main entry point for the traffic analyzer application.
"""

import sys
import click
from traffic_analyzer.src.gui.main_window import MainWindow
from PyQt6.QtWidgets import QApplication

@click.command()
@click.option('--interface', '-i', help='Network interface to capture packets from')
@click.option('--filter', '-f', help='BPF filter to apply')
@click.option('--gui/--no-gui', default=True, help='Run with GUI (default: True)')
def main(interface, filter, gui):
    """NetScan - Advanced Network Traffic Analysis Tool"""
    if gui:
        app = QApplication(sys.argv)
        window = MainWindow()
        if interface:
            window.set_interface(interface)
        if filter:
            window.set_filter(filter)
        window.show()
        sys.exit(app.exec())
    else:
        # TODO: Implement CLI mode
        click.echo("CLI mode not implemented yet")

if __name__ == '__main__':
    main() 