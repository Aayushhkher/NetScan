#!/bin/bash

# Exit on error
set -e

# Function to check if a command exists
command_exists() {
    command -v "$1" >/dev/null 2>&1
}

# Function to check if running as root
check_root() {
    if [ "$EUID" -ne 0 ]; then 
        echo "Please run as root (use sudo)"
        exit 1
    fi
}

# Function to setup Python environment
setup_python_env() {
    echo "Setting up Python environment..."
    
    # Check if Python 3.11 is installed
    if ! command_exists python3.11; then
        echo "Installing Python 3.11..."
        brew install python@3.11
    fi
    
    # Create virtual environment if it doesn't exist
    if [ ! -d "venv" ]; then
        echo "Creating virtual environment..."
        python3.11 -m venv venv
    fi
    
    # Activate virtual environment and install dependencies
    echo "Installing dependencies..."
    source venv/bin/activate
    python3.11 -m pip install --upgrade pip
    python3.11 -m pip install -r requirements.txt
    python3.11 -m pip install -e .
}

# Function to run the analyzer
run_analyzer() {
    echo "Starting traffic analyzer..."
    source venv/bin/activate
    python3.11 -m traffic_analyzer "$@"
}

# Main script
main() {
    # Check if running as root
    check_root
    
    # Parse command line arguments
    if [ "$1" = "setup" ]; then
        setup_python_env
        echo "Setup complete!"
    elif [ "$1" = "gui" ]; then
        # Ensure environment is set up
        if [ ! -d "venv" ]; then
            setup_python_env
        fi
        run_analyzer --gui
    else
        echo "Usage:"
        echo "  sudo ./run_analyzer.sh setup  - Set up the environment"
        echo "  sudo ./run_analyzer.sh gui     - Run the GUI application"
        exit 1
    fi
}

# Run main function with all arguments
main "$@"