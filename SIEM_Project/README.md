# Hybrid Enterprise SIEM & Automated Incident Response

## 1. Introduction

This project is a beginner-level Python-based Security Information and Event Management (SIEM) prototype. It analyzes security log files and identifies selected suspicious patterns.

## 2. Objectives

* Analyze security log files.
* Detect failed login patterns.
* Identify selected suspicious activities.
* Generate a security report.
* Learn basic Blue Team and Security Operations Center (SOC) concepts.

## 3. Tools Used

* Kali Linux
* Python 3
* Linux system logs
* Nano text editor
* VMware

## 4. Project Features

* Reads sample security logs.
* Analyzes collected Kali system logs.
* Detects selected failed-login and suspicious-activity patterns.
* Counts analyzed log lines and alerts.
* Saves results in a text report.

## 5. Project Structure

```text
SIEM_Project/
├── logs/
│   ├── security.log
│   └── system_logs.log
├── scripts/
│   └── log_monitor.py
└── reports/
    └── security_report.txt
```

## 6. How to Run

Run the following command in Kali Linux:

```bash
python3 ~/SIEM_Project/scripts/log_monitor.py
```

## 7. Results

During the sample test, the script analyzed 105 log lines and generated 3 alerts:

* Two failed-login alerts.
* One suspicious-activity alert.

These three alerts came from simulated sample logs. No matching suspicious patterns were detected in the collected system logs during this test.

## 8. Limitations

This is a learning prototype, not a complete enterprise SIEM. It uses simple pattern matching and cannot detect every type of cyberattack. The project does not yet provide automated incident response.

## 9. Future Improvements

* Integrate a full SIEM platform such as Wazuh.
* Improve detection rules.
* Add alert notifications.
* Develop automated incident-response playbooks.
* Test detection using controlled, authorized security scenarios.

## 10. Disclaimer

This project is for educational purposes. Sample security events are simulated and should not be treated as evidence of real attacks.
