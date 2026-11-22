# 🛡️ AUDITRON

**Assess. Analyze. Assure.**

Windows Security Auditing & Configuration Drift Detection Platform

AUDITRON is an educational cybersecurity auditing platform developed using Python and Streamlit. It inspects selected Windows security configurations, identifies potential security weaknesses, performs preliminary risk analysis, and detects configuration changes.

The platform provides a centralized dashboard for security auditing and configuration monitoring. It follows a read-only approach and does not automatically modify system security settings.

---

## Project Information

- **Project Name:** AUDITRON
- **Project Category:** Auditing
- **Platform:** Windows 11
- **Programming Language:** Python
- **Framework:** Streamlit
- **Version:** 2.2
- **Project Type:** Educational Cybersecurity Project

## Table of Contents

1. [Project Objectives](#1-project-objectives)
2. [Main Features](#2-main-features)
3. [Technologies Used](#3-technologies-used)
4. [Project Structure](#4-project-structure)
5. [Installation](#5-installation)
6. [How to Use](#6-how-to-use)
7. [Testing](#7-testing)
8. [Security and Ethical Considerations](#8-security-and-ethical-considerations)
9. [Rules of Engagement](#9-rules-of-engagement-roe)
10. [Legal Disclaimer](#10-legal-disclaimer)
11. [Data Handling](#11-data-handling)
12. [Scope and Limitations](#12-scope-and-limitations)
13. [Future Improvements](#13-future-improvements)

---

## 1. Project Objectives

The main objectives of AUDITRON are to:

- Inspect selected Windows security configurations.
- Identify potential security weaknesses and configuration issues.
- Establish a reference security configuration baseline.
- Detect configuration changes through baseline comparison.
- Classify security findings using rule-based risk levels.
- Generate downloadable security audit reports.
- Promote ethical, authorized, and responsible security auditing.

## 2. Main Features

### 2.1 CIS Benchmark Checker

Inspects selected Windows security controls:

- Windows Firewall
- Microsoft Defender
- Third-Party Antivirus Provider Detection
- SMBv1 Protocol

The checker displays five possible audit statuses:

| Status | Description |
|---|---|
| **PASS** | The checked security requirement is satisfied. |
| **FAIL** | A security configuration does not meet the requirement. |
| **WARNING** | Manual verification or further investigation is required. |
| **INFO** | Informational finding that does not independently indicate failure. |
| **ERROR** | The security check could not be completed reliably. |

> **Important:** AUDITRON checks selected Windows security controls. It is not a complete CIS Benchmark assessment and does not provide official CIS certification.

### 2.2 Configuration Drift Detector

Monitors changes in selected Windows security configurations.

**Main capabilities:**

- Create and save a security configuration baseline.
- Collect current system configuration data.
- Compare current settings against the saved baseline.
- Identify new, missing, or modified controls.
- Display configuration differences.
- Present configuration status separately from the current security assessment.

**Configuration comparison statuses:**

| Status | Description |
|---|---|
| **NO CHANGE** | The current configuration matches the saved baseline. |
| **DRIFT DETECTED** | A configuration value has changed from the baseline. |
| **NEW CONTROL** | A control exists in the current configuration but not in the baseline. |
| **MISSING CONTROL** | A control exists in the baseline but is missing from the current configuration. |

> **Note:** A configuration that matches the baseline is not automatically considered secure. The security assessment must also be reviewed.

### 2.3 Risk Analyzer

Provides preliminary, rule-based risk classification based on audit findings.

**Risk classifications:**

| Risk Level | Description |
|---|---|
| **HIGH** | A significant security issue requires attention. |
| **MEDIUM** | A potential security concern requires review. |
| **LOW** | The checked control meets the configured requirement. |
| **INFORMATIONAL** | The finding provides useful security information. |
| **UNDETERMINED** | The result requires further investigation. |

Each finding may include:

- Finding ID
- Security control
- Audit status
- Risk level
- Risk score
- Priority
- Risk explanation
- Recommended action
- Finding details

> **Important:** AUDITRON uses its own rule-based scoring methodology. Its risk scores are not official CVSS scores and should not be interpreted as formal business-impact ratings.

### 2.4 Report Generator

Generates downloadable CSV security audit reports.

The report contains the following information:

| No. | Report Field |
|---:|---|
| 1 | Generated At |
| 2 | Finding ID |
| 3 | Control |
| 4 | Audit Status |
| 5 | Risk Level |
| 6 | Risk Score |
| 7 | Priority |
| 8 | Risk Explanation |
| 9 | Recommendation |
| 10 | Details |

Reports allow users to review, organize, and document security audit findings.

### 2.5 Safety Manager

Provides basic operational safeguards:

- Authorization confirmation before security operations.
- Validation of permitted operations.
- Read-only operational mode.
- No automatic security remediation.
- Authorization checks before permitted analysis and report operations.

These safeguards are intended to reduce accidental or unauthorized use. They do not replace formal organizational authorization procedures.

## 3. Technologies Used

| Technology | Purpose |
|---|---|
| Python | Main application development |
| Streamlit | Interactive security dashboard |
| PowerShell | Windows security configuration collection |
| Windows Security PowerShell modules | Retrieve selected security information |
| JSON | Store configuration baselines and audit history |
| CSV | Export security audit reports |
| Python unittest | Automated unit testing |
| Pandas | Dashboard data presentation |

## 4. Project Structure

```text
AUDITRON/
│
├── main.py
├── requirements.txt
├── README.md
├── LICENSE
├── .gitignore
│
├── modules/
│   ├── __init__.py
│   ├── system_collector.py
│   ├── cis_checker.py
│   ├── drift_detector.py
│   ├── risk_analyzer.py
│   ├── report_generator.py
│   └── safety_manager.py
│
├── tests/
│   ├── test_cis_checker.py
│   ├── test_drift_detector.py
│   ├── test_risk_analyzer.py
│   ├── test_report_generator.py
│   └── test_safety_manager.py
│
├── output/
│   └── .gitkeep
│
└── docs/
```

Generated baseline and audit-history files are stored locally in the `output/` directory. These files are excluded from the public repository to prevent accidental disclosure of system information.

## 5. Installation

### 5.1 Requirements

Before installing AUDITRON, ensure that the following are available:

- Windows 11
- Python 3.13 or a compatible Python 3 version
- PowerShell
- Internet connection for initial dependency installation

Some security information depends on the Windows PowerShell security modules and permissions available to the current user.

### 5.2 Clone the Repository

```bash
git clone YOUR_GITHUB_REPOSITORY_URL
```

Replace `YOUR_GITHUB_REPOSITORY_URL` with the actual public GitHub repository URL.

Navigate to the project directory:

```bash
cd AUDITRON
```

### 5.3 Install Dependencies

```bash
python -m pip install -r requirements.txt
```

### 5.4 Run AUDITRON

```bash
python -m streamlit run main.py
```

Open the local address displayed in the terminal.

The default address is:

```text
http://localhost:8501
```

## 6. How to Use

Follow these steps to perform a security audit:

1. Launch the AUDITRON application.
2. Review the authorization and safety notices.
3. Confirm that you have permission to audit the computer.
4. Open **CIS Benchmark Audit**.
5. Run the security audit.
6. Review the results and security control findings.
7. Open **Configuration Drift**.
8. Create a security baseline.
9. Compare the current configuration against the saved baseline.
10. Review the configuration changes and security assessment.
11. Open **Risk Analysis** to review risk classifications and recommendations.
12. Open **Report Center** to generate and download the CSV report.

### Important Usage Notes

- Create a baseline before performing configuration comparisons.
- A saved baseline is retained when current dashboard results are cleared.
- Risk analysis and report generation use the latest CIS audit results.
- Confirm authorization before performing security operations.
- Protect generated reports because they may contain information about the audited computer.

## 7. Testing

AUDITRON uses Python's built-in `unittest` framework to test its modules.

### 7.1 Run All Unit Tests

```bash
python -m unittest discover -s tests -v
```

### 7.2 Run Individual Module Tests

**CIS Benchmark Checker:**

```bash
python -m unittest discover -s tests -p "test_cis_checker.py" -v
```

**Configuration Drift Detector:**

```bash
python -m unittest discover -s tests -p "test_drift_detector.py" -v
```

**Risk Analyzer:**

```bash
python -m unittest discover -s tests -p "test_risk_analyzer.py" -v
```

**Report Generator:**

```bash
python -m unittest discover -s tests -p "test_report_generator.py" -v
```

**Safety Manager:**

```bash
python -m unittest discover -s tests -p "test_safety_manager.py" -v
```

### 7.3 Testing Coverage

The tests cover areas such as:

- Security control status classification.
- Configuration baseline comparison.
- Risk classification and scoring.
- CSV report generation and input validation.
- Authorization and permitted-operation validation.

Test results should be based on the latest actual test execution.

## 8. Security and Ethical Considerations

AUDITRON is developed for educational and authorized cybersecurity auditing.

Users must:

- Audit only computers they own or have explicit permission to inspect.
- Confirm the authorized scope before performing an assessment.
- Follow applicable organizational security policies.
- Use the tool only for its intended read-only auditing functions.
- Protect generated reports and local audit information.
- Avoid publishing sensitive system information without permission.

## 9. Rules of Engagement (RoE)

### 9.1 Authorized Scope

The initial project is intended for auditing the local Windows computer on which AUDITRON is running.

Only systems and configurations covered by explicit authorization may be assessed.

### 9.2 Permitted Activities

- Read-only collection of selected Windows security configurations.
- Inspection of selected security controls.
- Creation of a local security configuration baseline.
- Comparison of current settings against the saved baseline.
- Rule-based risk analysis.
- Local generation of CSV audit reports.

### 9.3 Prohibited Activities

- Unauthorized access to computers or networks.
- Exploitation of vulnerabilities.
- Modification or disabling of security controls through AUDITRON.
- Unauthorized collection or disclosure of sensitive information.
- Use of audit findings to disrupt system operations.
- Assessment beyond the approved scope.

### 9.4 Time Window

Auditing should be performed during an approved assessment period and in accordance with the system owner's instructions.

### 9.5 Emergency Stop

Stop the assessment if unexpected system behavior, operational disruption, or an authorization issue occurs.

The user can stop the application by pressing `Ctrl + C` in the terminal running Streamlit.

Do not continue an assessment if permission has been withdrawn.

## 10. Legal Disclaimer

AUDITRON is an educational cybersecurity project and is not intended to facilitate unauthorized access or unlawful computer activities.

Users are responsible for obtaining appropriate authorization and complying with applicable laws, including Malaysia's Computer Crimes Act 1997 (Act 563), where applicable.

This project does not constitute legal advice or a guarantee of regulatory compliance.

## 11. Data Handling

- Audit information is processed locally by the application.
- Configuration baselines and audit history may be stored in the local `output/` directory.
- CSV reports may contain information about the audited computer.
- Users should review and protect reports before sharing them.
- Generated audit data and sensitive information should not be committed to a public repository.

## 12. Scope and Limitations

Current project limitations include:

- The initial platform focuses on Windows 11.
- Only selected Windows security controls are inspected.
- Third-party antivirus detection identifies registered providers but does not independently verify active protection.
- Microsoft Defender findings must be interpreted in the context of installed antivirus configurations.
- Configuration drift detection depends on the available baseline and collected controls.
- Risk classifications are preliminary rule-based assessments, not official CVSS calculations.
- AUDITRON does not provide automatic remediation.
- The tool is not a replacement for a professional security assessment.

## 13. Future Improvements

Potential future enhancements include:

- Expand the number of inspected Windows security controls.
- Improve third-party antivirus protection-status verification.
- Introduce additional risk assessment factors.
- Support PDF and other report formats.
- Improve historical audit comparison.
- Enhance configuration drift visualization.
- Introduce additional security compliance frameworks.

---

**AUDITRON — Assess. Analyze. Assure.**

*Promoting ethical, responsible, and informed cybersecurity auditing.*