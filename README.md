# NetScan - Real-Time Network Traffic Analyzer

A powerful Python-based tool for real-time network traffic monitoring and analysis.

## Features

- Real-time packet capture and analysis
- Interactive dashboard with protocol distribution
- Network activity timeline visualization
- Active connection monitoring
- Safety analysis for suspicious traffic
- Session-based traffic recording

## Requirements

- Python 3.11+
- PyQt6
- TShark (Wireshark CLI)
- Matplotlib
- NumPy

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Aayushhkher/NetScan.git
cd NetScan
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

4. Install TShark:
- macOS: `brew install wireshark`
- Linux: `sudo apt-get install tshark`
- Windows: Download from Wireshark website

## Usage

Run the application:
```bash
cd traffic_analyzer/src
sudo python main.py --gui
```

## License

Copyright (c) 2025 Aayush Kher. All Rights Reserved.

This software is proprietary and confidential. Unauthorized copying, modification, distribution, or use of this software is strictly prohibited. For licensing inquiries, please contact the copyright holder.

## Author

Aayush Kher

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. 