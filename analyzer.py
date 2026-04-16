from collections import defaultdict

log_file = "logs.txt"
alert_file = "alerts.txt"

failed_attempts = defaultdict(int)

def analyze_logs():
    with open(log_file, "r") as file:
        logs = file.readlines()

    alerts = []

    for log in logs:
        parts = log.split(" ")
        ip = parts[0]
        request = " ".join(parts[5:])

        # Detect brute force (multiple POST requests)
        if "POST" in request:
            failed_attempts[ip] += 1

            if failed_attempts[ip] >= 3:
                alerts.append(f"[ALERT] Possible brute force from IP: {ip}")

        # Detect suspicious admin access
        if "/admin" in request:
            alerts.append(f"[WARNING] Admin access attempt from IP: {ip}")

    return alerts


def save_alerts(alerts):
    with open(alert_file, "w") as file:
        for alert in alerts:
            file.write(alert + "\n")


if __name__ == "__main__":
    alerts = analyze_logs()
    save_alerts(alerts)

    print("Analysis complete. Alerts generated:")
    for alert in alerts:
        print(alert)