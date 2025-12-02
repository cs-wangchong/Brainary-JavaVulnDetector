# Java Security Detector

**Intelligent Java vulnerability detection powered by Brainary's multi-agent architecture**

[![Python Version](https://img.shields.io/badge/python-3.8%2B-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)

An intelligent, autonomous security vulnerability detection system for Java applications that combines LLM reasoning with static analysis tools for accurate, context-aware detection.

## 🚀 Quick Start

### Installation

```bash
# Install from source
git clone <repository-url>
cd java_security_detector
python -m pip install -e .

# Or install from PyPI (when published)
python -m pip install brainary-java-security
```

**Note:** On macOS with conda, always use `python -m pip` instead of just `pip` to ensure installation in the correct environment. See [INSTALL.md](INSTALL.md) for detailed installation instructions.

### Basic Usage

```python
from java_security_detector import JavaSecurityDetector

# Create detector
detector = JavaSecurityDetector()

# Quick scan
result = detector.quick_scan("path/to/java/project")
print(result["summary"])

# Export report
detector.export_report("security_report.txt")
```

### Command Line Interface

```bash
# Quick scan
java-security-scan /path/to/java/project

# Thorough scan with validation
java-security-scan /path/to/project --thorough

# Focus on specific vulnerabilities
java-security-scan /path/to/project --focus injection xss

# Export report
java-security-scan /path/to/project --output report.txt --format json

# List all vulnerability patterns
java-security-scan --list-patterns

# Get info about a specific vulnerability
java-security-scan --pattern-info CWE-89
```

## ✨ Key Features

- **🤖 Multi-Agent Architecture**: 4-agent pipeline (Scanner → Analyzer → Validator → Reporter)
- **🧠 LLM-Powered Intelligence**: Deep security reasoning beyond pattern matching
- **🔍 CodeQL Integration**: Industry-standard static analysis (optional)
- **📚 Comprehensive Knowledge Base**: 15 OWASP Top 10 and CWE patterns
- **🎯 High Accuracy**: Intelligent validation reduces false positives
- **🔧 Automated Remediation**: Specific, actionable fix recommendations
- **⚙️ Configurable**: Quick scan or thorough analysis modes
- **📊 Multiple Export Formats**: TXT, JSON, HTML reports

## 🏗️ Architecture

### Multi-Agent Pipeline

```
┌─────────────────┐
│ ScannerAgent    │  Initial scanning and triage
│ (Analyst)       │  - Pattern matching
│                 │  - Static analysis
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ AnalyzerAgent   │  Deep security analysis
│ (Researcher)    │  - LLM reasoning
│                 │  - Attack vector analysis
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ ValidatorAgent  │  Validation & false positive elimination
│ (Reviewer)      │  - Multi-perspective checking
│                 │  - Confidence assessment
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│ ReporterAgent   │  Results compilation & reporting
│ (Writer)        │  - Detailed reports
│                 │  - Remediation guidance
└─────────────────┘
```

### Domain-Specific Primitives

- **ThinkSecurityPrimitive**: Security-focused reasoning
- **AnalyzeCodePrimitive**: Code analysis with tool integration
- **DetectVulnerabilityPrimitive**: Targeted vulnerability detection
- **ValidateFindingPrimitive**: Deep validation
- **RecommendFixPrimitive**: Fix recommendations

## 🛡️ Vulnerability Coverage

### Supported Vulnerabilities (15 patterns)

| CWE | Name | Severity | OWASP |
|-----|------|----------|-------|
| CWE-89 | SQL Injection | Critical | A03 |
| CWE-502 | Insecure Deserialization | Critical | A08 |
| CWE-78 | OS Command Injection | Critical | A03 |
| CWE-79 | Cross-Site Scripting | High | A03 |
| CWE-22 | Path Traversal | High | A01 |
| CWE-611 | XML External Entity | High | A05 |
| CWE-798 | Hardcoded Credentials | High | A07 |
| CWE-327 | Weak Cryptography | High | A02 |
| CWE-90 | LDAP Injection | High | A03 |
| CWE-918 | SSRF | High | A10 |
| CWE-470 | Unsafe Reflection | High | - |
| CWE-330 | Weak Random | Medium | A02 |
| CWE-772 | Resource Leak | Medium | - |
| CWE-362 | Race Condition | Medium | - |
| CWE-476 | NULL Pointer | Low | - |

## 📖 Usage Examples

### Python API

```python
from java_security_detector import JavaSecurityDetector, DetectionConfig

# Thorough scan with custom config
config = DetectionConfig(
    deep_analysis=True,          # Enable LLM analysis
    validate_findings=True,      # Validate with LLM
    generate_remediation=True,   # Generate fixes
    max_findings=50,             # Limit findings
    focus_areas=["injection"],   # Focus areas
    confidence_threshold="high"  # Min confidence
)

detector = JavaSecurityDetector()
result = detector.detect("path/to/project", config)

# Access results
print(f"Total: {result['statistics']['total_findings']}")
print(f"Validated: {result['statistics']['validated_findings']}")

# Export in different formats
detector.export_report("report.txt", format="txt")
detector.export_report("report.json", format="json")
detector.export_report("report.html", format="html")
```

### Knowledge Base

```python
from java_security_detector import VulnerabilityKnowledgeBase

kb = VulnerabilityKnowledgeBase()

# List all patterns
print(kb.get_all_patterns_summary())

# Get specific pattern
pattern = kb.get_pattern("CWE-89")
print(f"{pattern.name}: {pattern.description}")

# Search patterns
results = kb.search("injection")

# Get detection guidance
print(kb.get_detection_guidance("CWE-89"))
```

### Individual Agents

```python
from java_security_detector import ScannerAgent, AnalyzerAgent
from brainary.core.context import ExecutionContext

context = ExecutionContext(program_id="security_scan")

# Use scanner
scanner = ScannerAgent()
scan_result = scanner.execute(context, "MyClass.java")

# Use analyzer
analyzer = AnalyzerAgent()
analysis_result = analyzer.execute(
    context,
    scan_result["findings"],
    focus_areas=["injection"]
)
```

## 🔧 Configuration

### Detection Modes

**Quick Scan** (Fast, pattern-based)
```python
result = detector.quick_scan("project/")
```

**Thorough Scan** (Deep, validated)
```python
result = detector.thorough_scan("project/", focus_areas=["injection"])
```

### DetectionConfig Options

```python
DetectionConfig(
    deep_analysis: bool = True,           # LLM analysis
    validate_findings: bool = True,       # LLM validation
    generate_remediation: bool = True,    # Fix recommendations
    max_findings: int = 50,               # Max findings
    focus_areas: List[str] = None,        # Vulnerability types
    confidence_threshold: str = "medium"  # Min confidence
)
```

## 📊 Output Format

```python
{
    "success": True,
    "target": "path/to/project",
    "statistics": {
        "total_findings": 15,
        "validated_findings": 10,
        "false_positives": 5
    },
    "findings": [
        {
            "cwe_id": "CWE-89",
            "name": "SQL Injection",
            "severity": "critical",
            "confidence": "high",
            "file": "UserDAO.java",
            "line": 42,
            "validated": True,
            "analysis": "...",
            "remediation": "..."
        }
    ],
    "report": "... detailed report ...",
    "summary": "... executive summary ..."
}
```

## 🧪 Examples

Run the comprehensive demo:

```bash
cd examples
python demo.py
```

The demo includes:
1. Knowledge base exploration
2. Quick scan demonstration
3. Thorough scan configuration
4. Multiple vulnerability detection
5. Pattern matching examples
6. Agent architecture overview
7. Knowledge base search

## 📋 Requirements

- Python 3.8+
- Brainary SDK (`python -m pip install brainary`)
- (Optional) CodeQL CLI for advanced static analysis

## 🚀 Development

### Setup Development Environment

```bash
# Clone repository
git clone <repository-url>
cd java_security_detector

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
python -m pip install -e ".[dev]"

# Run demo
python examples/demo.py
```

### Running Tests

```bash
pytest tests/ -v
```

### Code Quality

```bash
# Format code
black java_security_detector/

# Lint
flake8 java_security_detector/

# Type checking
mypy java_security_detector/
```

## 🤝 Integration

### CI/CD Pipeline

```yaml
# .github/workflows/security.yml
- name: Security Scan
  run: |
    python -m pip install brainary-java-security
    java-security-scan src/ --output report.json --format json
    # Fail if critical vulnerabilities found
    if [ $(jq '.statistics.critical' report.json) -gt 0 ]; then
      exit 1
    fi
```

### Pre-commit Hook

```bash
#!/bin/bash
# .git/hooks/pre-commit
java-security-scan . --quick --no-validation
```

## 📚 Documentation

- [Full Documentation](README_FULL.md)
- [API Reference](docs/API.md)
- [Examples](examples/)
- [Knowledge Base](docs/KNOWLEDGE_BASE.md)

## 🎯 Use Cases

- **Security Audits**: Thorough vulnerability assessment
- **Code Reviews**: Automated security checks
- **CI/CD Integration**: Continuous security testing
- **Developer Training**: Learn secure coding practices
- **Compliance**: OWASP Top 10 coverage

## 🔬 How It Works

1. **Scanning**: Pattern matching and static analysis find potential issues
2. **Analysis**: LLM analyzes code for deep understanding of vulnerabilities
3. **Validation**: Multi-perspective checking eliminates false positives
4. **Reporting**: Generate detailed reports with remediation guidance

## 🌟 Advantages

- **Context-Aware**: Understands business logic and intent
- **Low False Positives**: Intelligent validation reduces noise
- **Actionable**: Provides specific fixes, not just warnings
- **Extensible**: Add custom patterns and rules
- **Autonomous**: Requires minimal configuration

## 📄 License

MIT License - see LICENSE file for details

## 🙏 Acknowledgments

Built with:
- **Brainary SDK**: Cognitive architecture framework
- **CodeQL**: Static analysis engine (optional)
- **OWASP**: Vulnerability classification
- **CWE**: Weakness enumeration

## 📞 Support

- Issues: [GitHub Issues](https://github.com/cs-wangchong/Brainary/issues)
- Documentation: [Full Docs](README_FULL.md)
- Examples: [examples/](examples/)

---

**Note**: This is an intelligent security tool combining automated detection with LLM reasoning. Always review findings and use professional security expertise for production deployments.
