# CodeShield AI

### AI-Assisted Source Code Security Scanner

CodeShield AI is a Python-based security analysis application that helps developers identify potential vulnerabilities in uploaded source code.

It combines rule-based static analysis, advanced security heuristics, finding validation, and optional local AI-assisted review.

Built for the CDF CyberSec Hackathon.

## Key Features

- Upload source code as a ZIP archive.
- Scan source files for potential security weaknesses.
- Detect patterns associated with SQL injection.
- Identify potential cross-site scripting (XSS).
- Flag potentially missing authentication in privileged Supabase Edge Functions.
- Identify overly permissive Supabase Row Level Security (RLS) policies.
- Review source code with a local AI model.
- Validate and deduplicate security findings.
- Display severity, affected files, line numbers, and code evidence.
- Provide remediation guidance and illustrative secure code examples.
- Export security assessment reports in HTML, Markdown, and PDF formats.

## Technology Stack

| Component | Technology |
|---|---|
| Programming language | Python 3.12 |
| User interface | Streamlit |
| Data processing | Pandas |
| AI integration | Ollama |
| AI model | Qwen2.5-Coder 3B |
| PDF generation | ReportLab |
| Security analysis | Static rules and heuristics |

## Project Structure

```text
CodeShield-AI/
├── app.py
├── advanced_scanner.py
├── security_validator.py
├── report_generator.py
├── requirements.txt
├── .gitignore
└── README.md
```

## Installation

### 1. Clone the repository

```bash
git clone YOUR_REPOSITORY_URL
cd CodeShield-AI
```

Replace YOUR_REPOSITORY_URL with the actual GitHub repository URL.

### 2. Create a virtual environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

On Windows:

```powershell
.venv\Scripts\activate
```

### 3. Install Python dependencies

```bash
python -m pip install -r requirements.txt
```

### 4. Set up Ollama for AI analysis

Install Ollama from:

https://ollama.com

Download the local coding model:

```bash
ollama pull qwen2.5-coder:3b
```

Ensure the Ollama service is running before enabling AI analysis.

The AI model runs locally. An external paid AI API is not required for the configured Ollama workflow.

### 5. Launch CodeShield AI

```bash
python -m streamlit run app.py
```

Open the local Streamlit address displayed in the terminal, usually:

http://localhost:8501

## How to Use

1. Launch the CodeShield AI application.
2. Open the scanner settings.
3. Enable AI-assisted review if Ollama is available.
4. Upload a ZIP archive containing source code.
5. Start the security scan.
6. Review detected vulnerabilities and severity levels.
7. Inspect the affected file paths, line numbers, and source evidence.
8. Review the recommended fixes and secure code examples.
9. Download the security assessment report.

## Security Detection

### SQL Injection

Identifies suspicious dynamic SQL construction patterns, including unsafe string interpolation and concatenation.

### Cross-Site Scripting

Identifies potentially unsafe HTML rendering patterns, including React's dangerouslySetInnerHTML.

### Authentication and Authorization

Flags privileged Supabase Edge Functions where caller authentication is not visibly validated.

### Row Level Security

Identifies potentially overly permissive Supabase SELECT policies, including policies using USING (true).

These detections are heuristic and require manual verification.

## AI-Assisted Analysis

CodeShield AI integrates with Ollama using the Qwen2.5-Coder 3B model.

The AI review supplements static detection by examining source code for potential security weaknesses.

AI review is optional and depends on the local model and Ollama service being available.

AI-generated findings may contain errors or omissions.

## Security Reports

CodeShield AI produces downloadable reports in three formats:

- HTML for browser-based review.
- Markdown for documentation and collaboration.
- PDF for sharing a structured security assessment.

Reports include findings, severity levels, affected files, source evidence, recommended remediation, and illustrative secure code examples.

## Validation and Testing

The project has been tested against a sample vulnerable application containing React, Supabase Edge Functions, and SQL policies.

During development, 23 targeted security test cases passed, covering detection behavior and recognition of selected secure alternatives.

A representative scan analyzed 19 source files and produced six potential findings:

| Severity | Findings |
|---|---:|
| Critical | 0 |
| High | 4 |
| Medium | 2 |
| Low | 0 |
| Total | 6 |

These results describe the tested sample, not general detection accuracy or production security guarantees.

## Security and Privacy

CodeShield AI performs static analysis of uploaded source code and does not intentionally execute the uploaded application.

The configured Ollama model runs locally.

Do not upload sensitive credentials or proprietary source code unless you are authorized to analyze it.

Security findings and suggested fixes require developer review and testing before deployment.

## Limitations

- Static analysis can produce false positives and false negatives.
- The scanner does not replace a professional security assessment.
- Cross-file behavior and external authentication settings may be missed.
- AI analysis is limited by model capabilities and source-code context.
- Suggested fixes are illustrative and must be adapted to the actual application.

## Hackathon

Developed for the CDF CyberSec Hackathon.

CodeShield AI demonstrates how static analysis and local AI can work together to support source-code security review.

## Disclaimer

This tool is intended for educational and authorized security analysis. Always verify findings and test remediations before applying them to production systems.
