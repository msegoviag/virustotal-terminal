#!/usr/bin/env python3

import hashlib
import os
import sys
import time
import requests

API_KEY = "YOUR_API_KEY"
VT_API_URL = "https://www.virustotal.com/api/v3"


def check_file(file_path):
    # Check whether a file has been provided as parameter
    if not file_path:
        print("A file must be provided as a parameter.")
        sys.exit(1)

    # Check if the selected file exist
    if not os.path.isfile(file_path):
        print(f"The file {file_path} does not exist.")
        sys.exit(1)

    # Calculate the SHA256 hash of the file
    with open(file_path, "rb") as f:
        sha256_hash = hashlib.sha256(f.read()).hexdigest()

    return sha256_hash


def check_file_analysis(sha256_hash):
    # Send a GET request to VirusTotal to check if the file has already been analyzed
    headers = {"x-apikey": API_KEY}
    response = requests.get(
        f"{VT_API_URL}/files/{sha256_hash}", headers=headers)

    if response.ok:
        response_json = response.json()
        print_detection_results(response_json)
        sys.exit()


def submit_file_for_analysis(file_path):
    # Send the file to VirusTotal for analysis
    headers = {"x-apikey": API_KEY}
    with open(file_path, "rb") as f:
        response = requests.post(
            f"{VT_API_URL}/files", headers=headers, files={"file": f})

    if not response.ok:
        print(
            f"Error submitting the file: {response.json()['error']['message']}")
        sys.exit(1)

    # Get file analysis ID
    analysis_id = response.json()["data"]["id"]
    print("The file is being analyzed. Please wait...")

    # Wait for VirusTotal to complete the analysis
    while True:
        time.sleep(15)
        response = requests.get(
            f"{VT_API_URL}/analyses/{analysis_id}", headers=headers)
        response_json = response.json()
        if "data" not in response_json:
            raise ValueError(
                f"API response does not contain data: {response_json}")
        status = response_json["data"]["attributes"]["status"]
        if status == "completed":
            break
        elif status == "queued":
            print("Your file is waiting in the queue for analysis...")
        elif status == "in_progress":
            print("Analysis is in progress, please wait...")
        elif status == "failure":
            print("Analysis failed. Please try again later.")
            sys.exit(1)
        elif status == "timeout":
            print("Analysis timed out. Please try again later.")
            sys.exit(1)
        elif status == "paused":
            print("Analysis paused. Please try again later.")
            sys.exit(1)
        elif status == "cancelled":
            print("Analysis cancelled. Please try again later.")
            sys.exit(1)

    # Obtain the result of the analysis
    response = requests.get(
        f"{VT_API_URL}/files/{check_file(file_path)}", headers=headers)
    response_json = response.json()
    print_detection_results(response_json)


def get_antivirus_detection_count(response_json):
    count = 0
    for engine, details in response_json["data"]["attributes"]["last_analysis_results"].items():
        if details["category"] == "malicious":
            count += 1
    return count


def print_detection_results(response_json):
    last_analysis_stats = response_json.get("data", {}).get(
        "attributes", {}).get("last_analysis_stats", {})
    found_threat = last_analysis_stats.get("malicious", 0) > 0

    if found_threat:
        print("\nTHREATS WERE FOUND:\n")
        detection_count = 0
        for engine, details in response_json["data"]["attributes"]["last_analysis_results"].items():
            print(f"{engine}: {details['category']}")
            if details["category"] == "malicious":
                detection_count += 1
        print(f"\n{detection_count} antivirus detected the file as malicious.")
    else:
        print("No threats were found.")
        print("The file is safe.")


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Missing file path argument.")
        sys.exit(1)
    try:
        # Check if the file has already been analyzed
        sha256_hash = check_file(sys.argv[1])
        check_file_analysis(sha256_hash)

        submit_file_for_analysis(sys.argv[1])
    except requests.RequestException as request:
        print(f"Error connecting to VirusTotal: {request}")
    except ValueError as value_error:
        print(value_error)
    except Exception as e:
        print(e)