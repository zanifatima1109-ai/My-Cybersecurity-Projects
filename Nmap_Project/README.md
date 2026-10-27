# Nmap Network Inventory Project

## About
This project uses Python to read an Nmap XML scan report
and generate an HTML network inventory report.

## Features
- Reads Nmap XML scan results.
- Lists discovered IP addresses.
- Displays host status and available MAC addresses.
- Counts active hosts.
- Generates an HTML report.

## Project Files
- nmap.py: Python script for generating the report.
- network_scan.xml: Nmap host-discovery results.
- scan_results.xml: Additional scan results.
- network_report.html: Generated HTML report.
- Wireshark_HTTP_Project.pcapng: Network traffic capture.

## Requirements
- Python 3
- Nmap XML output file

## How to Run
1. Open a terminal in this project folder.
2. Make sure network_scan.xml exists.
3. Run:

   python3 nmap.py

4. Open network_report.html in a web browser.

## Important Note
The script processes an existing XML report.
It does not perform a new network scan.

Only scan networks you own or have permission to test.
