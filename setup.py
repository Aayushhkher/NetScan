from setuptools import setup, find_packages

setup(
    name="traffic_analyzer",
    version="0.1",
    packages=find_packages(),
    install_requires=[
        'scapy>=2.5.0',
        'pyshark>=0.6.0',
        'click>=8.1.0',
        'rich>=13.0.0',
        'PyQt6>=6.4.0',
        'pandas>=2.0.0',
        'matplotlib>=3.7.0',
        'python-dotenv>=1.0.0',
        'pytest>=7.0.0'
    ],
) 