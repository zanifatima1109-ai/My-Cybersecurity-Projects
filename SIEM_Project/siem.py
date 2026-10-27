from datetime import datetime
from pathlib import Path

# Mini SIEM Security Log Monitoring Project

PROJECT_DIR = Path.home() / "SIEM_Project"
LOG_FILE = PROJECT_DIR / "security.log"
ALERT_FILE = PROJECT_DIR / "alerts.log"
REAL_LOG_FILE = PROJECT_DIR / "system_logs.txt"


def create_sample_logs():
    """Create sample security logs for testing."""

    sample_logs = [
        "INFO: System started successfully",
        "INFO: User kali logged in",
        "FAILED LOGIN: User admin from 192.168.1.10",
        "FAILED LOGIN: User admin from 192.168.1.10",
        "FAILED LOGIN: User test from 192.168.1.20",
        "INFO: System running normally",
    ]

    with open(LOG_FILE, "w", encoding="utf-8") as file:
        for log in sample_logs:
            file.write(log + "\n")


def monitor_logs():
    """Detect repeated failed logins in sample logs."""

    print("\n===== MINI SIEM SECURITY MONITOR =====")

    failed_attempts = {}

    with open(LOG_FILE, "r", encoding="utf-8") as file:
        logs = file.readlines()

    for log in logs:
        print("[LOG]", log.strip())

        if "FAILED LOGIN" in log:
            parts = log.strip().split(" from ")

            if len(parts) == 2:
                ip_address = parts[1]
                failed_attempts[ip_address] = (
                    failed_attempts.get(ip_address, 0) + 1
                )

    alerts = []

    for ip_address, count in failed_attempts.items():
        if count >= 2:
            message = (
                f"WARNING: {count} failed login attempts "
                f"from IP {ip_address}"
            )

            alerts.append(message)
            print("\n[SECURITY ALERT]", message)

    with open(ALERT_FILE, "a", encoding="utf-8") as file:
        for alert in alerts:
            timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            file.write(f"[{timestamp}] {alert}\n")

    print("\nTotal sample log entries:", len(logs))
    print("Total sample security alerts:", len(alerts))


def monitor_real_logs():
    """Scan collected system logs for suspicious login-related entries."""

    print("\n===== REAL SYSTEM LOG MONITOR =====")

    if not REAL_LOG_FILE.exists():
        print("System log file not found!")
        return

    suspicious_words = [
        "failed password",
        "authentication failure",
        "invalid user",
        "permission denied",
    ]

    total_alerts = 0
    real_alerts = []

    with open(
        REAL_LOG_FILE,
        "r",
        encoding="utf-8",
        errors="ignore"
    ) as file:

        for line in file:
            if any(word in line.lower() for word in suspicious_words):
                print("[REVIEW]", line.strip())
                real_alerts.append(line.strip())
                total_alerts += 1

    if not real_alerts:
        print("No matching suspicious login entries found.")

    # Save matching real-log entries in the alerts file.
    if real_alerts:
        with open(ALERT_FILE, "a", encoding="utf-8") as file:
            for alert in real_alerts:
                timestamp = datetime.now().strftime(
                    "%Y-%m-%d %H:%M:%S"
                )
                file.write(
                    f"[{timestamp}] REAL LOG REVIEW: {alert}\n"
                )

    print("Total matching entries:", total_alerts)
    print("Real-log alerts saved to:", ALERT_FILE)


def main():
    create_sample_logs()
    monitor_logs()
    monitor_real_logs()


if __name__ == "__main__":
    main()

