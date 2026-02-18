from datetime import datetime

def generate_report(target, open_ports, os_result, findings):
    filename = f"scan_report_{target.replace('.', '_')}.txt"

    with open(filename, "w") as report:
        report.write("===== SECURITY SCAN REPORT =====\n")
        report.write(f"Target: {target}\n")
        report.write(f"Scan Date: {datetime.now()}\n\n")

        report.write("---- Open Ports ----\n")
        if open_ports:
            for port in open_ports:
                report.write(f"Port {port} is OPEN\n")
        else:
            report.write("No open ports detected.\n")

        report.write("\n---- OS Detection ----\n")
        report.write(f"{os_result}\n")

        report.write("\n---- Vulnerability Assessment ----\n")
        for issue, risk in findings:
            report.write(f"{issue} | Risk Level: {risk}\n")

        report.write("\n===== END OF REPORT =====\n")

    print(f"\n[+] Report saved as {filename}")
