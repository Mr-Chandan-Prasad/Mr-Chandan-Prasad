# AI-Assisted Broken Authentication Scanner

This project provides a rule-based scanner for authentication cookies with AI-assisted interpretation and reporting. It targets common broken authentication indicators such as missing cookie flags, short session tokens, and low entropy values. The AI layer never invents findings and only interprets the deterministic results from the scanner.

## Features

- Single target, list, or file-based scanning
- Deterministic cookie analysis and severity scoring
- AI-assisted summaries, business risk, and remediation guidance
- JSON and text report generation

## Project Layout

```
.
├── app.py
├── config.py
└── core
    ├── analyzer.py
    ├── cookie_utils.py
    └── entropy.py
```

## Usage

Install dependencies:

```
pip install requests
```

Scan a single target:

```
python app.py --target https://example.com
```

Scan multiple targets:

```
python app.py --target https://example.com --target https://testsite.com
```

Scan from a file:

```
python app.py --target-file targets.txt
```

Reports are written to the `reports/` directory by default.

## Notes

- Entropy is estimated with Shannon entropy per character.
- AI output is derived only from rule-based findings to prevent hallucinated vulnerabilities.
