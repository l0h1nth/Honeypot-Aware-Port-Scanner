import json
from datetime import datetime
import os
def save_log(data):
    if not os.path.exists("logs"):
        os.makedirs("logs")
    filename = "logs/scan_results.json"
    with open(filename, "w") as f:
        json.dump(data, f, indent=4)
    print(f"\nResults saved to {filename}")
