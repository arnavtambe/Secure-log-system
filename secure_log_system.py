import hashlib
import json
import os
import datetime

LOG_FILE = "secure_logs.json"


# ---------------- HASH FUNCTION ----------------
def calculate_hash(data):
    return hashlib.sha256(data.encode()).hexdigest()


# ---------------- LOG ENTRY ----------------
class LogEntry:
    def __init__(self, timestamp, event_type, description, prev_hash):
        self.timestamp = timestamp
        self.event_type = event_type
        self.description = description
        self.prev_hash = prev_hash
        self.hash = self.generate_hash()

    def generate_hash(self):
        data = f"{self.timestamp}{self.event_type}{self.description}{self.prev_hash}"
        return calculate_hash(data)

    def to_dict(self):
        return {
            "timestamp": self.timestamp,
            "event_type": self.event_type,
            "description": self.description,
            "prev_hash": self.prev_hash,
            "hash": self.hash
        }


# ---------------- LOG SYSTEM ----------------
class SecureLogSystem:
    def __init__(self):
        self.logs = []
        self.load_logs()

    # Load logs from file
    def load_logs(self):
        if os.path.exists(LOG_FILE):
            with open(LOG_FILE, "r") as file:
                self.logs = json.load(file)
        else:
            self.create_genesis_log()

    # Save logs to file
    def save_logs(self):
        with open(LOG_FILE, "w") as file:
            json.dump(self.logs, file, indent=4)

    # Create first log
    def create_genesis_log(self):
        genesis = LogEntry(str(datetime.datetime.now()), "GENESIS", "Start of Log", "0")
        self.logs.append(genesis.to_dict())
        self.save_logs()

    # Add new log
    def add_log(self, event_type, description):
        prev_hash = self.logs[-1]["hash"]
        new_log = LogEntry(str(datetime.datetime.now()), event_type, description, prev_hash)
        self.logs.append(new_log.to_dict())
        self.save_logs()
        print("✅ Log added successfully")

    # Display logs
    def display_logs(self):
        for i, log in enumerate(self.logs):
            print("\n---------------------------")
            print(f"Log {i}")
            for key, value in log.items():
                print(f"{key}: {value}")

    # Verify integrity
    def verify_logs(self):
        print("\n🔍 Verifying log integrity...\n")

        for i in range(1, len(self.logs)):
            current = self.logs[i]
            previous = self.logs[i - 1]

            recalculated_hash = calculate_hash(
                f"{current['timestamp']}{current['event_type']}{current['description']}{current['prev_hash']}"
            )

            # Check modification
            if current["hash"] != recalculated_hash:
                print(f"❌ TAMPER DETECTED at log {i} (data modified)")
                return False

            # Check chain linkage
            if current["prev_hash"] != previous["hash"]:
                print(f"❌ CHAIN BROKEN at log {i} (reorder/delete detected)")
                return False

        print("✅ All logs are secure and intact")
        return True


# ---------------- CLI MENU ----------------
def main():
    system = SecureLogSystem()

    while True:
        print("\n====== Secure Log System ======")
        print("1. Add Log")
        print("2. View Logs")
        print("3. Verify Logs")
        print("4. Exit")

        choice = input("Enter choice: ")

        if choice == "1":
            event = input("Enter event type: ")
            desc = input("Enter description: ")
            system.add_log(event, desc)

        elif choice == "2":
            system.display_logs()

        elif choice == "3":
            system.verify_logs()

        elif choice == "4":
            break

        else:
            print("Invalid choice")


if __name__ == "__main__":
    main()