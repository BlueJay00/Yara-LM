#!/usr/bin/env python

__description__ = 'Matching YARA rules within log files'
__author__ = 'BlueJay00'
__version__ = '0.0.04'
__date__ = '2023/02/05'

# Author: BlueJay00

"""
History:
  2024/02/04: start v0.0.01
  2024/02/05: continue v0.0.02
  2024/02/05: continue v0.0.03
  2024/02/05: first publication v0.0.04
  2024/02/06: added ReadMe and requirements.txt
  
Todo:
- Logging: Implement a logging mechanism to record script activities and errors, providing a log file for troubleshooting.
- Customizable Output Formats: Allow options to choose the output format (e.g., JSON, CSV, plain text) based on preference.
- YARA Rule Versioning: Support different versions of YARA rules and allow to specify which version to use.
- Parallel Processing: Enhance performance by implementing parallel processing, especially when dealing with a large number of logs or complex YARA rules.
- Configurability: Extend the configuration options to include parameters such as the maximum context lines, maximum match count, or other.
- Rule Exclusion: Allow users to specify YARA rules to be excluded during the analysis.
- Interactive Mode: Implement an interactive mode where users can choose specific logs or YARA rules to analyze.
- Rule Metadata: Display additional metadata information from YARA rules, such as rule descriptions, authors, or modification dates.
- Rule Repository Integration: Connect to an online repository of YARA rules and allow users to download and update rules directly from the repository. Unsure yet!!!
- Integration with SIEM Tools: Enable integration with SIEM tools for centralized log management and analysis. Unsure yet!!!
- Alert Severity Levels: Assign severity levels to alerts based on the importance or potential impact of the detected alerts. Unsure yet!!!
- Regular Expression Support: Extend the script to support regular expressions within YARA rules for more advanced pattern matching. Unsure yet!!!
- Rule Whitelisting/Blacklisting: Allow to define rules or specific patterns to be whitelisted or blacklisted.

"""

import os
import yara
import json

# Path to the folder containing your logs (eg:web server access logs, web application logs, etc),
# and especially those yara rules matching on certain exploitation characteristics,
# on web shells or C2 traffic generating certain type of URLs and web requests, and so on.

log_folder_path = "path/to/logs"  # Replace with your actual log folder path

# Path to the folder containing YARA rule files (use your own repository,
# or try the Awesome-Yara rules repository that can be found in GitHub
# at https://github.com/InQuest/awesome-yara).

yara_rules_folder_path = "path/to/yara_rules"  # Replace with your actual YARA rules folder path

# List of YARA rules file names with either .yar or .yara extensions

yara_rules = [os.path.join(yara_rules_folder_path, rule_file) for rule_file in os.listdir(yara_rules_folder_path) if rule_file.endswith((".yar", ".yara"))]

# Number of lines to include before and after a match in the output

context_lines = 3

# Number of times a match can occur before aggregation is performed

max_match_count = 3

# Maximum number of alerts to display

max_alerts_to_display = 100


def read_logs_from_folder(folder_path):
    log_data = {}
    for filename in os.listdir(folder_path):
        if filename.endswith(".log"):
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, "r", encoding="utf-8") as log_file:
                    log_data[file_path] = log_file.readlines()
            except FileNotFoundError:
                print(f"File not found: {file_path}")
    return log_data

def apply_yara_rules(log_data, rule_files):
    matches = []
    for rule_file in rule_files:
        compiled_rules = yara.compile(filepath=rule_file)
        for log_file, log_lines in log_data.items():
            match_contexts = {}
            for i, line in enumerate(log_lines):
                if compiled_rules.match(data=line):
                    match_context = get_match_context(log_lines, i, context_lines)
                    match_hash = hash((rule_file, log_file, match_context))
                    if match_hash not in match_contexts:
                        match_contexts[match_hash] = {
                            "rule": os.path.basename(rule_file),
                            "log_file": log_file,
                            "line_numbers": [i + 1],
                            "context": match_context
                        }
                    else:
                        match_contexts[match_hash]["line_numbers"].append(i + 1)

            matches.extend(match_contexts.values())

    return matches

def get_match_context(lines, match_line_index, context_lines):
    start_index = max(0, match_line_index - context_lines)
    end_index = min(len(lines), match_line_index + context_lines + 1)
    return lines[start_index:end_index]

def aggregate_matches(matches):
    aggregated_alerts = {}
    for idx, match in enumerate(matches, start=1):
        alert_key = (match["rule"], match["log_file"], tuple(match["context"]))
        if alert_key not in aggregated_alerts:
            alert_title = f"Alert{idx:03}"
            aggregated_alerts[alert_key] = {
                "title": alert_title,
                "rule": match["rule"],
                "log_file": match["log_file"],
                "line_numbers": match["line_numbers"],
                "context": match["context"]
            }
        else:
            aggregated_alerts[alert_key]["line_numbers"].extend(match["line_numbers"])

    return list(aggregated_alerts.values())

def truncate_alerts(alerts, max_alerts):
    if len(alerts) > max_alerts:
        print(f"Truncating output at {max_alerts} alerts. Try again with fewer log files or fewer YARA rules to match with.")
        return alerts[:max_alerts]
    return alerts

def main():
    # Read logs from the folder containing log files
    logs = read_logs_from_folder(log_folder_path)

    if logs:
        matches = []
        for rule_file in yara_rules:
            # Apply fetched YARA rules to the aforementioned logs
            rule_matches = apply_yara_rules(logs, [rule_file])
            matches.extend(rule_matches)

        # Aggregate matches
        aggregated_alerts = aggregate_matches(matches)

        # Truncate output if there are more than max_alerts_to_display
        truncated_alerts = truncate_alerts(aggregated_alerts, max_alerts_to_display)

        # Output results in JSON format with Alert titles numbered
        json_output = json.dumps(truncated_alerts, indent=2)
        print(json_output)

 
if __name__ == "__main__":
    Main()
