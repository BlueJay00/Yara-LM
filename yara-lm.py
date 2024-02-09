#!/usr/bin/env python

__description__ = 'Matching YARA rules within log files'
__author__ = 'BlueJay00'
__version__ = '0.0.2'
__date__ = '2023/02/09'


"""
History:
  2024/02/04: start v0.0.01
  2024/02/05: continue v0.0.02
  2024/02/05: continue v0.0.03
  2024/02/05: first publication v0.0.04
  2024/02/06: added ReadMe and requirements.txt
  2024/02/07: csv output format added v.0.0.1
  2024/02/07: plain text out format added v.0.0.11
  2024/02/09: changed context into an option v.0.0.2
  
Todo:
- Add more customizable Output Formats: Include other outputs (like xml, html) based on preference.
- Logging: Implement a logging mechanism to record script activities and errors, providing a log file for troubleshooting.
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
import csv
import argparse

# CONFIGURATION

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


# END CONFIGURATION


# Section to read log files from the specified folder path containing the logs to review
# For now, only log files ending in .log are included, more extensions to be added later

def read_logs_from_folder(folder_path):
    log_data = {}
    for filename in os.listdir(folder_path):
        if filename.endswith(".log"):
            file_path = os.path.join(folder_path, filename)
            try:
                with open(file_path, "r", encoding="utf-8") as log_file:
                    log_data[file_path] = log_file.readlines()
            except FileNotFoundError:
                print(f"File ending with .log not found in: {file_path}")
    return log_data

# Section to read and match from the given yara rules from the specified folder path
# using the yara python to handle yara rule format and have access to the full potential
# of YARA in python scripts.
# Imported YARA rules get first compiled and then enumerated to attempt then to match
# them with the previously loaded and read log files lines.

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
                            "matched_lines": [line.strip()]
                        }
                    else:
                        match_contexts[match_hash]["line_numbers"].append(i + 1)
                        match_contexts[match_hash]["matched_lines"].append(line.strip())

            matches.extend(match_contexts.values())

    return matches

# Provides the context (3 lines above, 3 lines below) for every line of log previously matched.

def get_match_context(lines, match_line_index, context_lines):
    start_index = max(0, match_line_index - context_lines)
    end_index = min(len(lines), match_line_index + context_lines + 1)
    return lines[start_index:end_index]

# Aggregates matches if more than 3 matches for the same yara rule are found for the same log file.
# Then, begins preparation of output by adding an numbered Alert title and what to do in aggregation of alerts.

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
                "matched_lines": match["matched_lines"],
                "aggregated": False
            }
        else:
            aggregated_alerts[alert_key]["line_numbers"].extend(match["line_numbers"])
            aggregated_alerts[alert_key]["matched_lines"].extend(match["matched_lines"])
            aggregated_alerts[alert_key]["aggregated"] = True

    return list(aggregated_alerts.values())

# Alerts get truncated at a maximum value of 100, returning a message if the value if reached.

def truncate_alerts(alerts, max_alerts):
    if len(alerts) > max_alerts:
        print(f"Truncating output at {max_alerts} alerts. Try again with fewer log files or fewer YARA rules to match with.")
        return alerts[:max_alerts]
    return alerts

# Write output in JSON format using json python library

def write_json_output(alerts):
    json_output = json.dumps(alerts, indent=2)
    with open("alerts.json", "w") as json_file:
        json_file.write(json_output)

# Write output in CSV format using csv python library

def write_csv_output(alerts):
    with open("alerts.csv", "w", newline='') as csv_file:
        fieldnames = ["title", "rule", "log_file", "line_numbers", "matched_lines", "aggregated"]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for alert in alerts:
            writer.writerow(alert)

# Write output in Plain Text format 

def write_plain_text_output(alerts):
    with open("alerts.txt", "w") as txt_file:
        for alert in alerts:
            txt_file.write(f"{alert['title']}:\n")
            txt_file.write(f"Rule: {alert['rule']}\n")
            txt_file.write(f"Log File: {alert['log_file']}\n")
            txt_file.write(f"Line Numbers: {', '.join(map(str, alert['line_numbers']))}\n")
            if not alert["aggregated"]:
                txt_file.write(f"Matched Lines:\n")
                for line in alert['matched_lines']:
                    txt_file.write(f"  {line.strip()}\n")
            txt_file.write("\n")

# Main function definition and point of execution, with the output format arguments and the context option.

def main(output_format, context_line):
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

        # Output results in the specified format (json as default) with Alerts titles numbered
        if output_format == "json":
            write_json_output(truncated_alerts)
        elif output_format == "csv":
            write_csv_output(truncated_alerts)
        elif output_format == "plain":
            write_plain_text_output(truncated_alerts)
        else:
            print("Invalid output format. Please choose 'json', 'csv' or 'plain'.")

        # Context option to provide context for a specified alert
        if context_line:
            for alert in truncated_alerts:
                if context_line in alert['line_numbers']:
                    print(f"Context for line {context_line}:")
                    context_start = max(alert['line_numbers'].index(context_line) - context_lines, 0)
                    context_end = min(context_start + (context_lines * 2) + 1, len(alert['line_numbers']))
                    for line_number, line in zip(alert['line_numbers'][context_start:context_end], alert['matched_lines'][context_start:context_end]):
                        print(f"Line {line_number}: {line.strip()}")

 
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="YARA rule-based log matching script")
    parser.add_argument("-o", "--output-format", choices=["json", "csv", "plain"], default="json", help="Output format (json, csv, plain)")
    parser.add_argument("-c", "--context", type=int, help="Line number to show context for")
    args = parser.parse_args()
    main(args.output_format, args.context)
