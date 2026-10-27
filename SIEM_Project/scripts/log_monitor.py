from datetime import datetime
from pathlib import Path

BASE_DIR = Path.home() / "SIEM_Project"

LOG_FILES = [
    BASE_DIR / "logs" / "security.log",
    BASE_DIR / "logs" / "system_logs.log"
]

REPORT_FILE = BASE_DIR / "reports" / "security_report.txt"

SUSPICIOUS_PATTERNS = [
    "FAILED_LOGIN",
    "SUSPICIOUS_ACTIVITY",
    "Failed password",
    "authentication failure"
]


def monitor_logs():
    alerts = []
    total_lines = 0

    print("=" * 50)
    print("       SIEM SECURITY LOG MONITOR")
    print("=" * 50)

    for log_file in LOG_FILES:
        print(f"\nAnalyzing: {log_file.name}")

        if not log_file.exists():
            print("[WARNING] Log file not found.")
            continue

        with log_file.open("r", encoding="utf-8", errors="replace") as file:
            for line in file:
                line = line.strip()

                if not line:
                    continue

                total_lines += 1

                for pattern in SUSPICIOUS_PATTERNS:
                    if pattern.lower() in line.lower():
                        alert = f"[ALERT] Pattern: {pattern} | Log: {log_file.name} | {line}"
                        alerts.append(alert)
                        print(alert)
                        break

    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    REPORT_FILE.parent.mkdir(parents=True, exist_ok=True)

    with REPORT_FILE.open("w", encoding="utf-8") as report:
        report.write("SIEM SECURITY REPORT\n")
        report.write(f"Generated: {timestamp}\n")
        report.write(f"Total log lines analyzed: {total_lines}\n")
        report.write(f"Total alerts: {len(alerts)}\n")
        report.write("=" * 50 + "\n\n")

        if alerts:
            for alert in alerts:
                report.write(alert + "\n")
        else:
            report.write("No matching suspicious patterns detected.\n")

    print("\n" + "=" * 50)
    print("Total log lines analyzed:", total_lines)
    print("Total alerts:", len(alerts))
    print("Report saved at:", REPORT_FILE)


if __name__ == "__main__":
    monitor_logs()
