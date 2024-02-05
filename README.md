# Yara-LM

## AKA

Yara-LM Also Known As Yara-LogMatcher

## Overview

This Python script automates the detection of potential threats found on any type of logs in a provided path, alerting on matching YARA rules. It reads logs from a specified path, iteratively applies YARA rules provided in a folder, aggregates and outputs matching alerts in JSON format. The script obviates consecutive matches within the same context and aggregates alerts if the same match occurs more than three times within the same log file. It outputs detailed information for each alert, including the YARA rule, log file that matched, the line numbers matched within the log file, and the context (3 lines above and 3 lines below), providing a comprehensive overview of potential alerts to investigate within the provided log data.

## Prerequisites

- Python 3.x
- YARA (https://yara.readthedocs.io/en/stable/)

## Setup

1. Clone or download the repository.

git clone https://github.com/BlueJay00/Yara-LM.git <br />
cd Yara-LM

2. Install the required components via PIP 

pip install -r requirements.txt

3. Adjust the script parameters

LOG_FOLDER_PATH = "path/to/logs" <br />
YARA_RULES_FOLDER_PATH = "path/to/yara_rules"

4. Optional adjustments

You can also change other paramerters, like the context lines (3 above and 3 below), or the maximum number alerts to display. But I do not recommend this for better performance and output analysis.

CONTEXT_LINES = 3 <br />
MAX_ALERTS_TO_DISPLAY = 100

## Usage

python yara-lm.py

The script will apply a defined pool of YARA rules to a defined number of log files and output aggregated alerts of macthes in JSON format.

## Sample Output

[ <br />
  { <br />
    "title": "Alert001", <br />
    "rule": "example_rule.yar", <br />
    "log_file": "path/to/logs/example.log", <br />
    "line_numbers": [42, 43, 44], <br />
    "context": [ <br />
      "Previous line 1", <br />
      "Previous line 2", <br />
      "Previous line 3", <br />
      "Matched line", <br />
      "Next line 1", <br />
      "Next line 2", <br />
      "Next line 3" <br />
    ] <br />
  }, <br />
  // ... (additional alerts) <br />
] <br />

## Notes

- Ensure YARA rules have either .yar or .yara extension.
- The script supports a maximum of 100 alerts. If more alerts are present, output is truncated. This number is customizable, but it is not recommended to increase it further.
- Adjust the content as needed, providing accurate paths and relevant details for your specific implementation.
 
