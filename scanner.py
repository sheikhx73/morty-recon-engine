import socket
import threading
import time
from queue import Queue

from vulnerability_checker import check_vulnerabilities
from report_generator import generate_report


# ==============================
# ANSI Colors (Clean Professional)
# ==============================
RED = "\033[91m"
GREEN = "\033[92m"
YELLOW = "\033[93m"
CYAN = "\033[96m"
RESET = "\033[0m"


# ==============================
# Configuration
# ==============================
THREAD_COUNT = 100
PORT_RANGE = 1025


# ==============================
# Professional MORTY Banner
# ==============================
def show_banner():
    print(CYAN + r"""
============================================================
   ███╗   ███╗ ██████╗ ██████╗ ████████╗██╗   ██╗
   ████╗ ████║██╔═══██╗██╔══██╗╚══██╔══╝╚██╗ ██╔╝
   ██╔████╔██║██║   ██║██████╔╝   ██║    ╚████╔╝ 
   ██║╚██╔╝██║██║   ██║██╔══██╗   ██║     ╚██╔╝  
   ██║ ╚═╝ ██║╚██████╔╝██║  ██║   ██║      ██║   
   ╚═╝     ╚═╝ ╚═════╝ ╚═╝  ╚═╝   ╚═╝      ╚═╝   

                    Recon Engine
============================================================
""" + RESET)
    print(CYAN + "Version: 1.0 | Mode: Standard Recon\n" + RESET)


# ==============================
# Port Scanner
# ==============================
def scan_port(target, port, open_ports):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)

        result = sock.connect_ex((target, port))

        if result == 0:
            print(GREEN + f"[OPEN] Port {port}" + RESET)
            open_ports.append(port)

            # Banner grabbing (basic HTTP probe)
            try:
                sock.send(b"HEAD / HTTP/1.1\r\nHost: " + target.encode() + b"\r\n\r\n")
                banner = sock.recv(1024).decode(errors="ignore")
                if banner:
                    first_line = banner.split("\n")[0]
                    print(YELLOW + f"       Banner: {first_line}" + RESET)
            except:
                pass

        sock.close()

    except:
        pass


# ==============================
# OS Detection
# ==============================
def detect_os(open_ports):
    if 80 in open_ports or 443 in open_ports:
        return "Web Server Detected (OS Cannot Be Determined)"
    elif 22 in open_ports:
        return "Likely Linux/Unix (SSH Open)"
    elif 3389 in open_ports:
        return "Likely Windows (RDP Open)"
    elif 445 in open_ports:
        return "Likely Windows (SMB Open)"
    else:
        return "Unknown"


# ==============================
# Worker Thread
# ==============================
def worker(target, queue, open_ports):
    while not queue.empty():
        port = queue.get()
        scan_port(target, port, open_ports)
        queue.task_done()


# ==============================
# Main Scanner Logic
# ==============================
def main():
    show_banner()

    target = input(CYAN + "Enter Target IP or Domain: " + RESET).strip()

    try:
        target_ip = socket.gethostbyname(target)
    except socket.gaierror:
        print(RED + "Unable to resolve target." + RESET)
        return

    print(CYAN + f"\nScanning Target: {target} ({target_ip})" + RESET)
    print(CYAN + "Scan Started...\n" + RESET)

    start_time = time.time()

    open_ports = []
    queue = Queue()

    for port in range(1, PORT_RANGE):
        queue.put(port)

    threads = []
    for _ in range(THREAD_COUNT):
        thread = threading.Thread(target=worker, args=(target_ip, queue, open_ports))
        thread.start()
        threads.append(thread)

    for thread in threads:
        thread.join()

    end_time = time.time()
    duration = round(end_time - start_time, 2)

    print(CYAN + "\n================ SCAN COMPLETE ================" + RESET)
    print(f"Open Ports: {open_ports}")

    # OS Detection
    os_result = detect_os(open_ports)
    print(f"OS Detection: {os_result}")

    # Vulnerability Assessment
    findings = check_vulnerabilities(open_ports)

    print("\nVulnerability Assessment:")
    for issue, risk in findings:
        if risk == "HIGH":
            print(RED + f"- {issue} | Risk: {risk}" + RESET)
        elif risk == "Medium":
            print(YELLOW + f"- {issue} | Risk: {risk}" + RESET)
        else:
            print(GREEN + f"- {issue} | Risk: {risk}" + RESET)

    print(CYAN + f"\nScan Duration: {duration} seconds" + RESET)

    # Generate Report
    generate_report(target, open_ports, os_result, findings)


if __name__ == "__main__":
    main()
