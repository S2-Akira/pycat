#PyCAT — Advanced Ethical Hacking CLI Tool

PyCAT is a powerful, all-in-one Python-based CLI tool designed for ethical penetration testing and client management. It supports remote client connections, remote shell access, and includes pentesting tools like SMB Null Session vulnerability checks — all integrated into a sleek, interactive CLI interface.

#Features

Async TCP Server to manage multiple connected clients

Remote Shell: Execute commands on connected clients

Pentesting Tools Menu:

SMB Null Session Check (using Impacket)

Easily extendable for malware builder, exploits, and more

User-friendly CLI with colored menus powered by Rich

Requirements
Python 3.7+

impacket library (for SMB functionality)

rich library (for enhanced CLI UI)

Install dependencies with:

bash
Copy
Edit
pip install impacket rich
Setup & Usage
1. Run the PyCAT Server
Run the main PyCAT script on your controlling machine (the server):

bash
Copy
Edit
python pycat.py
This will start a TCP server listening on all interfaces, port 9001, waiting for client connections.

2. Connect Clients
You need client machines running a Python client script that auto-connects back to your PyCAT server on port 9001. (You can generate or create your own client script.)

3. Use the CLI Menu
After starting the server, you will see the menu:

markdown
Copy
Edit
1. List clients
2. Select client and start shell
3. Pentesting tools
0. Exit
List clients: View all currently connected clients.

Select client and start shell: Start a remote shell session to send commands to a connected client.

Pentesting tools: Open a submenu with pentesting tools.

4. Pentesting Tools
Selecting pentesting tools (3) opens a submenu:

pgsql
Copy
Edit
1. SMB Null Session Check
0. Back to main menu
SMB Null Session Check: Enter a target IP to test if SMB shares can be accessed anonymously via a Null Session using the Impacket library. If vulnerable, it lists accessible shares.

5. Exiting
Select option 0 at the main menu to safely exit PyCAT.

Notes & Warnings
Use responsibly: Only run penetration tests against systems you have explicit permission to test.

The SMB Null Session check requires SMB port 445 to be open and accessible on the target.

Client machines must run a compatible client script that connects back to your PyCAT server.

You can extend PyCAT with additional pentesting modules, exploits, or a malware builder as needed.

****
