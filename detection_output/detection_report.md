# Java Security Detection Report

**Target:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java`
**Generated:** N/A
**Processing Time:** 123ms

## Summary

- **Total Findings:** 20
- **Critical:** 0
- **High:** 0
- **Medium:** 0
- **Low:** 0

## Findings

### 1. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/XmlProcessor.java:22`
**CWE:** N/A

**Description:**
XML External Entity (XXE): XML parser configured to process external entities

**Vulnerable Code:**
```java
DocumentBuilderFactory.newInstance()
```

---

### 2. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/XmlProcessor.java:43`
**CWE:** N/A

**Description:**
XML External Entity (XXE): XML parser configured to process external entities

**Vulnerable Code:**
```java
DocumentBuilderFactory.newInstance()
```

---

### 3. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/XmlProcessor.java:55`
**CWE:** N/A

**Description:**
XML External Entity (XXE): XML parser configured to process external entities

**Vulnerable Code:**
```java
SAXParserFactory.newInstance()
```

---

### 4. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/XmlProcessor.java:81`
**CWE:** N/A

**Description:**
XML External Entity (XXE): XML parser configured to process external entities

**Vulnerable Code:**
```java
TransformerFactory.newInstance()
```

---

### 5. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/DataProcessor.java:36`
**CWE:** N/A

**Description:**
Resource Leak: Resources not properly closed, causing memory/resource leaks

**Vulnerable Code:**
```java
new FileInputStream(filename)
```

---

### 6. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/DataProcessor.java:57`
**CWE:** N/A

**Description:**
Resource Leak: Resources not properly closed, causing memory/resource leaks

**Vulnerable Code:**
```java
new BufferedReader(
                new InputStreamReader(process.getInputStream()
```

---

### 7. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/SessionManager.java:54`
**CWE:** N/A

**Description:**
Cross-Site Scripting (XSS): Untrusted data rendered in HTML without proper encoding

**Vulnerable Code:**
```java
.write("User " + userId +
```

---

### 8. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/SessionManager.java:24`
**CWE:** N/A

**Description:**
Race Condition: Concurrent access to shared resources without proper synchronization

**Vulnerable Code:**
```java
if (username != null && password != null) {
            HttpSession session = request.getSession(true);
            session.setAttribute("username", username);
            session.setAttribute("password", password); // Storing password in session!
            
            // Set insecure cookie without HttpOnly and Secure flags
            Cookie cookie = new Cookie("sessionId", session.getId());
            cookie.setMaxAge(3600);
            // Missing: cookie.setHttpOnly(true);
            // Missing: cookie.setSecure(true);
            response.addCookie(cookie);
            
            // Store sensitive data in cookie
            Cookie userCookie = new Cookie("userdata", username + ":" + password);
            response.addCookie(userCookie);
            
            response.getWriter().write(
```

---

### 9. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/SessionManager.java:68`
**CWE:** N/A

**Description:**
Race Condition: Concurrent access to shared resources without proper synchronization

**Vulnerable Code:**
```java
if (session != null) {
            session.setAttribute("password", newPassword);
            response.getWriter().write(
```

---

### 10. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/SessionManager.java:97`
**CWE:** N/A

**Description:**
Race Condition: Concurrent access to shared resources without proper synchronization

**Vulnerable Code:**
```java
if (session != null) {
            // Should invalidate old session and create new one
            session.setAttribute("authenticated", true);
            session.setAttribute(
```

---

### 11. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/FileUploadServlet.java:50`
**CWE:** N/A

**Description:**
Cross-Site Scripting (XSS): Untrusted data rendered in HTML without proper encoding

**Vulnerable Code:**
```java
.write("File uploaded successfully: " +
```

---

### 12. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/FileUploadServlet.java:54`
**CWE:** N/A

**Description:**
Cross-Site Scripting (XSS): Untrusted data rendered in HTML without proper encoding

**Vulnerable Code:**
```java
.write("Upload failed: " +
```

---

### 13. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/FileUploadServlet.java:86`
**CWE:** N/A

**Description:**
Cross-Site Scripting (XSS): Untrusted data rendered in HTML without proper encoding

**Vulnerable Code:**
```java
.write("File not found: " +
```

---

### 14. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/FileUploadServlet.java:74`
**CWE:** N/A

**Description:**
Resource Leak: Resources not properly closed, causing memory/resource leaks

**Vulnerable Code:**
```java
new FileInputStream(file)
```

---

### 15. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/CryptoManager.java:81`
**CWE:** N/A

**Description:**
Weak Random Number Generation: Use of predictable random number generators for security purposes

**Vulnerable Code:**
```java
new Random(
```

---

### 16. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/UserController.java:31`
**CWE:** N/A

**Description:**
SQL Injection: Untrusted data concatenated into SQL queries without proper sanitization

**Vulnerable Code:**
```java
"SELECT * FROM users WHERE username='" +
```

---

### 17. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/UserController.java:67`
**CWE:** N/A

**Description:**
SQL Injection: Untrusted data concatenated into SQL queries without proper sanitization

**Vulnerable Code:**
```java
"SELECT * FROM users WHERE name LIKE '%" +
```

---

### 18. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/UserController.java:39`
**CWE:** N/A

**Description:**
Cross-Site Scripting (XSS): Untrusted data rendered in HTML without proper encoding

**Vulnerable Code:**
```java
.write("<h1>Welcome " + username +
```

---

### 19. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/UserController.java:42`
**CWE:** N/A

**Description:**
Cross-Site Scripting (XSS): Untrusted data rendered in HTML without proper encoding

**Vulnerable Code:**
```java
.write("Login failed for user: " +
```

---

### 20. Unknown

**Severity:** Unknown
**Location:** `/Users/chongwang/Workspace/CodeHub/Brainary-Projects/Brainary-JavaVulnDetector/test_project/src/main/java/com/example/vulnerable/UserController.java:51`
**CWE:** N/A

**Description:**
Cross-Site Scripting (XSS): Untrusted data rendered in HTML without proper encoding

**Vulnerable Code:**
```java
.write("Database error: " +
```

---

## Detection Statistics

- Total Scans: 1
- Total Findings: 20
- Validated Findings: 0
- False Positives Filtered: 0
- Remediations Generated: 0
