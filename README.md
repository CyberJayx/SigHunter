# SigHunter

SigHunter is a lightweight desktop triage utility engineered using Python's native UI platform. It serves as an offline threat detection rule and log validator, allowing Tier-2 SOC analysts to verify the accuracy of custom security rules against raw event log fields without risking deployment issues inside enterprise production environments.

## Practical Capabilities
* **Interactive Triage Space:** Clean split-pane graphical interface built for instant text log analysis.
* **On-the-Fly Verification:** Evaluates custom text conditions against complex raw log strings in seconds.
* **MITRE ATT&CK Logic Mapping:** Automatically matches specific malicious behaviors (like hidden PowerShell executions) to industry-standard adversary profiles.
* **Zero Dependency Core:** Runs perfectly on any basic administrative workstation using standard, out-of-the-box Python installations.

## How to Install and Run

1. Pull this code repository down to your secure workstation platform:
   ```bash
   git clone [https://github.com/YOUR_USERNAME/SigHunter.git](https://github.com/YOUR_USERNAME/SigHunter.git)
   cd SigHunter
