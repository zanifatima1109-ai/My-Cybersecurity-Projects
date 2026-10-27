import xml.etree.ElementTree as ET
from html import escape
from datetime import datetime

# Read the Nmap XML file
tree = ET.parse("network_scan.xml")
root = tree.getroot()

rows = []
total_hosts = 0

# Read each discovered host
for host in root.findall("host"):

    status_element = host.find("status")
    status = (
        status_element.get("state", "Unknown")
        if status_element is not None
        else "Unknown"
    )

    ip_address = "Unknown"
    mac_address = "Not available"

    for address in host.findall("address"):
        if address.get("addrtype") == "ipv4":
            ip_address = address.get("addr")
        elif address.get("addrtype") == "mac":
            mac_address = address.get("addr")

    if status == "up":
        total_hosts += 1

    rows.append(
        "<tr>"
        f"<td>{escape(ip_address)}</td>"
        f"<td>{escape(status)}</td>"
        f"<td>{escape(mac_address)}</td>"
        "</tr>"
    )

# Create the HTML report
html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Nmap Network Inventory</title>

<style>
body {{
    font-family: Arial, sans-serif;
    margin: 35px;
    background: #f4f6f9;
    color: #222;
}}

h1 {{
    text-align: center;
}}

.summary {{
    background: white;
    padding: 18px;
    margin-bottom: 20px;
    border-radius: 8px;
}}

table {{
    width: 100%;
    border-collapse: collapse;
    background: white;
}}

th, td {{
    border: 1px solid #ddd;
    padding: 12px;
    text-align: left;
}}

th {{
    background: #243447;
    color: white;
}}

tr:nth-child(even) {{
    background: #f2f2f2;
}}

footer {{
    margin-top: 20px;
    font-size: 13px;
}}
</style>
</head>

<body>

<h1>Nmap Network Asset Inventory</h1>

<div class="summary">
    <h2>Scan Summary</h2>
    <p><strong>Active hosts discovered:</strong> {total_hosts}</p>
    <p><strong>Report generated:</strong> {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>
    <p><strong>Source:</strong> network_scan.xml</p>
</div>

<h2>Discovered Devices</h2>

<table>
<thead>
<tr>
    <th>IP Address</th>
    <th>Status</th>
    <th>MAC Address</th>
</tr>
</thead>
<tbody>
{''.join(rows)}
</tbody>
</table>

<footer>
    This report contains host-discovery results.
    Open ports were not scanned in this discovery scan.
</footer>

</body>
</html>
"""

# Save the HTML report
with open("network_report.html", "w", encoding="utf-8") as file:
    file.write(html)

print("HTML report created successfully!")
print("File: network_report.html")
print("Active hosts discovered:", total_hosts)