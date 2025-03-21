# Network Traffic Analyzer

A real-time network traffic analyzer with a modern GUI interface built in Python. Captures and displays network packets using TShark, showing protocols, IPs, and statistics. Features interactive filtering, protocol analysis, and a live dashboard for network monitoring.

## Features

- Real-time packet capture and display
- Modern PyQt6-based GUI interface
- Protocol-specific filtering (TCP, UDP, HTTP, DNS, ICMP)
- Live network statistics dashboard
- Detailed packet information display
- Network interface selection
- Custom BPF filter support

## Requirements

- Python 3.11+
- PyQt6
- TShark (Wireshark)
- Matplotlib
- Pandas

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Aayushhkher/network-traffic-analyzer.git
cd network-traffic-analyzer
```

2. Create and activate a virtual environment:
```bash
python -m venv .venv
source .venv/bin/activate  # On Windows: .venv\Scripts\activate
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
sudo python3.11 run_analyzer.py --gui
```

## License

MIT License - see LICENSE file for details

## Author

Aayush Kher 