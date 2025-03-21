# NetScan

A real-time network traffic analyzer with a modern GUI interface built in Python. Captures and displays network packets using TShark, showing protocols, IPs, and statistics. Features interactive filtering, protocol analysis, and a live dashboard for network monitoring.

## Features

- Real-time packet capture and display
- Modern PyQt6-based GUI interface
- Protocol-specific filtering (TCP, UDP, HTTP, DNS, ICMP)
- Live network statistics dashboard
- Detailed packet information display
- Network interface selection
- Custom BPF filter support
- Session management and data persistence
- Interactive packet analysis tools

## Requirements

- Python 3.11+
- PyQt6
- TShark (Wireshark)
- Matplotlib
- Pandas
- Scapy
- Click
- Rich

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Aayushhkher/NetScan.git
cd NetScan
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv311
source .venv311/bin/activate  # On Windows: .venv311\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Install TShark (Wireshark):
- macOS: `brew install wireshark`
- Linux: `sudo apt-get install wireshark`
- Windows: Download from [Wireshark website](https://www.wireshark.org/download.html)

## Usage

Run the application with sudo privileges (required for packet capture):
```bash
sudo python -m traffic_analyzer
```

Or with specific options:
```bash
sudo python -m traffic_analyzer --interface eth0 --filter "tcp port 80" --gui
```

## Features in Detail

- **Real-time Monitoring**: Live capture and display of network traffic
- **Protocol Analysis**: Detailed breakdown of various network protocols
- **Filtering**: Support for both GUI-based and BPF filters
- **Statistics**: Live graphs and statistics for network usage
- **Session Management**: Save and load capture sessions
- **Export**: Export captured data for further analysis

## License

MIT License - see LICENSE file for details

## Author

Aayush Kher 