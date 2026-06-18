# Detection as Code (DaC) Enterprise Architecture

This repository manages SIEM detection rules for both **Splunk** and **IBM QRadar** using a GitOps/DaC pipeline. 

All rules are mapped to the **OWASP Top 10 2025** framework and inspired by **Sigma** standards.

## Architecture Flow
1. Rules are modified or added inside `splunk/rules.json` or `qradar/rules.json`.
2. On `git push` to the `main` branch, a **GitHub Actions** workflow triggers.
3. Python automation scripts sync the detection rules directly to SIEM environments via APIs.