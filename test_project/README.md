# Vulnerable Test Java Application

This is a test Java project with **intentional security vulnerabilities** for testing the Java Security Detector.

## ⚠️ WARNING
This application contains real security vulnerabilities and should **NEVER** be deployed in production or exposed to the internet. It is for security testing purposes only.

## Vulnerabilities Included

### 1. SQL Injection (CWE-89)
- **File**: `UserController.java`
- **Lines**: Multiple locations
- User input directly concatenated into SQL queries

### 2. Cross-Site Scripting (XSS) (CWE-79)
- **File**: `UserController.java`, `FileUploadServlet.java`
- Reflecting user input without sanitization

### 3. Hardcoded Credentials (CWE-798)
- **File**: `UserController.java`
- Database credentials hardcoded in source code

### 4. Path Traversal (CWE-22)
- **File**: `FileUploadServlet.java`
- User-controlled file paths without validation

### 5. Unrestricted File Upload (CWE-434)
- **File**: `FileUploadServlet.java`
- No file type validation

### 6. Weak Cryptography (CWE-327)
- **File**: `CryptoManager.java`
- Use of DES and MD5 algorithms
- Static IV in AES encryption
- Insecure random number generation

### 7. Insecure Deserialization (CWE-502)
- **File**: `DataProcessor.java`
- Deserializing untrusted data

### 8. Command Injection (CWE-78)
- **File**: `DataProcessor.java`
- User input passed to system commands

### 9. Missing Authentication (CWE-306)
- **File**: `SessionManager.java`
- Sensitive operations without authentication

### 10. Insecure Session Management (CWE-614)
- **File**: `SessionManager.java`
- Cookies without HttpOnly/Secure flags
- Session fixation vulnerability

### 11. XML External Entity (XXE) (CWE-611)
- **File**: `XmlProcessor.java`
- Multiple XXE vulnerabilities in XML parsers

### 12. Vulnerable Dependencies
- **File**: `pom.xml`
- Log4j 2.14.1 (CVE-2021-44228 - Log4Shell)
- Commons FileUpload 1.3.3 (known vulnerabilities)

## Project Structure

```
test_project/
├── pom.xml
└── src/
    └── main/
        └── java/
            └── com/
                └── example/
                    └── vulnerable/
                        ├── UserController.java       (SQL Injection, XSS, Hardcoded Creds)
                        ├── FileUploadServlet.java    (Path Traversal, Unrestricted Upload)
                        ├── CryptoManager.java        (Weak Crypto)
                        ├── DataProcessor.java        (Deserialization, Command Injection)
                        ├── SessionManager.java       (Auth/Session Issues)
                        └── XmlProcessor.java         (XXE)
```

## Running Detection

From the parent directory (java_security_detector):

```bash
# Scan the entire test project
java-security-scan test_project/src

# Scan with verbose output
java-security-scan test_project/src --verbose

# Generate HTML report
java-security-scan test_project/src --format html --output test_results.html

# Generate JSON report
java-security-scan test_project/src --format json --output test_results.json
```

## Expected Results

The detector should identify:
- **High Severity**: SQL Injection, Command Injection, Insecure Deserialization, XXE
- **Medium Severity**: XSS, Path Traversal, Weak Cryptography
- **Low Severity**: Information Exposure, Missing Authentication

Total: ~20-30 vulnerabilities across 6 files
