# ThreatLens

**Security Log Analysis & Incident Investigation Platform**

ThreatLens is a beginner-friendly cybersecurity portfolio project that analyzes authentication-style CSV logs, highlights suspicious patterns, and provides a dashboard for reviewing events and documenting an investigation.

## Features

- Upload a CSV file or use the included synthetic demo dataset
- Summary metrics and event charts
- Heuristic alerts for repeated failed logins, one IP touching multiple accounts, and a success after recent failures
- Searchable and filterable event explorer
- CSV exports for alerts and filtered events
- Session-only investigation notes and case status

## Requirements

- Python 3.11–3.15
- Internet access for the first package installation

## Run locally on Windows

1. Extract the ZIP file.
2. Open the extracted `ThreatLens` folder in Visual Studio Code.
3. Open **Terminal → New Terminal**.
4. Install dependencies:

   ```powershell
   python -m pip install -r requirements.txt
   ```

5. Start the dashboard:

   ```powershell
   python -m streamlit run app.py
   ```

6. Streamlit should open the dashboard in your browser. If it does not, follow the local URL shown in the terminal.

## CSV format

The required columns are `event_time`, `source_ip`, `username`, `event_type`, and `status`. Timestamps should be parseable by pandas. The app also recognizes common aliases such as `timestamp`, `ip`, `user`, `event`, and `result`.

## Important limitations

- The included logs are synthetic examples, not real threat intelligence.
- Alert rules are simple heuristics. An alert is an investigation lead, not proof of malicious activity.
- Investigation notes and case status are stored only in the current app session and are not persistent.
- This starter app has no user authentication or role-based access control. Do not upload confidential or sensitive logs to a public deployment.
- Use only data you are authorized to analyze.

## Suggested next steps

1. Test with the included sample data.
2. Add input validation and tests.
3. Add persistent case storage and authentication before handling sensitive data.
4. Publish the code to a GitHub repository and deploy through Streamlit Community Cloud when ready.
