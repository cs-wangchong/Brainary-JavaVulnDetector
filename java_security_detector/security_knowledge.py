"""
Security Knowledge Initialization

Initialize semantic memory with security knowledge:
- OWASP Top 10 patterns (semantic memory)
- CWE vulnerability patterns (semantic memory)
- Remediation templates (procedural memory)
- Detection skills (skill memory)
"""

from typing import List, Dict, Any
from brainary.memory.semantic import SemanticMemory
import logging

logger = logging.getLogger(__name__)


def initialize_security_knowledge(semantic_memory: SemanticMemory) -> None:
    """
    Initialize semantic memory with comprehensive security knowledge.
    
    Args:
        semantic_memory: SemanticMemory instance to populate
    """
    logger.info("Initializing security knowledge base")
    
    # 1. OWASP Top 10 (Semantic Knowledge)
    _load_owasp_patterns(semantic_memory)
    
    # 2. Common CWE Patterns (Semantic Knowledge)
    _load_cwe_patterns(semantic_memory)
    
    # 3. Remediation Templates (Procedural Knowledge)
    _load_remediation_templates(semantic_memory)
    
    # 4. Detection Skills (Skill Memory)
    _load_detection_skills(semantic_memory)
    
    logger.info("Security knowledge base initialized")


def _load_owasp_patterns(memory: SemanticMemory) -> None:
    """Load OWASP Top 10 patterns."""
    owasp_patterns = [
        {
            "name": "Injection",
            "owasp_id": "A03:2021",
            "description": "SQL, NoSQL, OS command injection vulnerabilities",
            "indicators": ["executeQuery", "Statement.execute", "Runtime.exec", "ProcessBuilder"],
            "severity": "Critical",
            "examples": "User input directly in SQL queries without parameterization"
        },
        {
            "name": "Broken Authentication",
            "owasp_id": "A07:2021",
            "description": "Authentication and session management flaws",
            "indicators": ["session", "password", "credential", "token"],
            "severity": "Critical",
            "examples": "Weak password storage, session fixation, missing authentication"
        },
        {
            "name": "Sensitive Data Exposure",
            "owasp_id": "A02:2021",
            "description": "Inadequate protection of sensitive data",
            "indicators": ["password", "creditCard", "ssn", "apiKey", "private"],
            "severity": "High",
            "examples": "Unencrypted sensitive data, weak encryption algorithms"
        },
        {
            "name": "XML External Entities (XXE)",
            "owasp_id": "A05:2021",
            "description": "XXE attacks through XML processing",
            "indicators": ["DocumentBuilder", "SAXParser", "XMLReader"],
            "severity": "High",
            "examples": "XML parsers with external entity processing enabled"
        },
        {
            "name": "Broken Access Control",
            "owasp_id": "A01:2021",
            "description": "Improper access restrictions",
            "indicators": ["authorize", "permission", "role", "admin"],
            "severity": "Critical",
            "examples": "Missing authorization checks, insecure direct object references"
        },
        {
            "name": "Security Misconfiguration",
            "owasp_id": "A05:2021",
            "description": "Insecure default configurations",
            "indicators": ["config", "settings", "default", "debug"],
            "severity": "High",
            "examples": "Debug mode enabled, default credentials, verbose errors"
        },
        {
            "name": "Cross-Site Scripting (XSS)",
            "owasp_id": "A03:2021",
            "description": "XSS vulnerabilities in web applications",
            "indicators": ["innerHTML", "document.write", "eval", "response.getWriter"],
            "severity": "High",
            "examples": "Unsanitized user input rendered in HTML"
        },
        {
            "name": "Insecure Deserialization",
            "owasp_id": "A08:2021",
            "description": "Unsafe object deserialization",
            "indicators": ["ObjectInputStream", "readObject", "XMLDecoder"],
            "severity": "Critical",
            "examples": "Deserializing untrusted data without validation"
        },
        {
            "name": "Using Components with Known Vulnerabilities",
            "owasp_id": "A06:2021",
            "description": "Vulnerable dependencies and libraries",
            "indicators": ["import", "dependency", "library", "version"],
            "severity": "High",
            "examples": "Outdated libraries with known CVEs"
        },
        {
            "name": "Insufficient Logging & Monitoring",
            "owasp_id": "A09:2021",
            "description": "Inadequate logging and monitoring",
            "indicators": ["log", "audit", "monitor", "alert"],
            "severity": "Medium",
            "examples": "Missing security event logging, no alerting mechanism"
        }
    ]
    
    for pattern in owasp_patterns:
        from brainary.memory.semantic import FactualKnowledge
        import uuid
        
        entry = FactualKnowledge(
            entry_id=f"owasp_{pattern['owasp_id']}_{uuid.uuid4().hex[:8]}",
            key_concepts=[pattern["name"], pattern["owasp_id"]],
            description=pattern["description"],
            entity=pattern["name"],
            properties=pattern,
            importance=0.9,
            metadata={"type": "owasp", "severity": pattern["severity"]}
        )
        memory.add_knowledge(entry)
    
    logger.info(f"Loaded {len(owasp_patterns)} OWASP patterns")


def _load_cwe_patterns(memory: SemanticMemory) -> None:
    """Load Common Weakness Enumeration patterns."""
    cwe_patterns = [
        {
            "cwe_id": "CWE-89",
            "name": "SQL Injection",
            "description": "Improper neutralization of SQL commands",
            "risk": "Critical",
            "detection": "Look for dynamic SQL construction with user input",
            "code_patterns": ["Statement.execute", "createStatement", "executeQuery with concatenation"]
        },
        {
            "cwe_id": "CWE-78",
            "name": "OS Command Injection",
            "description": "Improper neutralization of OS commands",
            "risk": "Critical",
            "detection": "Check Runtime.exec and ProcessBuilder with user input",
            "code_patterns": ["Runtime.getRuntime().exec", "ProcessBuilder", "Runtime.exec"]
        },
        {
            "cwe_id": "CWE-79",
            "name": "Cross-site Scripting",
            "description": "Improper neutralization of input during web page generation",
            "risk": "High",
            "detection": "Unsanitized user input in HTML output",
            "code_patterns": ["response.getWriter().write", "out.println", "innerHTML"]
        },
        {
            "cwe_id": "CWE-502",
            "name": "Deserialization of Untrusted Data",
            "description": "Unsafe deserialization of external data",
            "risk": "Critical",
            "detection": "ObjectInputStream.readObject without validation",
            "code_patterns": ["ObjectInputStream", "readObject", "XMLDecoder.readObject"]
        },
        {
            "cwe_id": "CWE-22",
            "name": "Path Traversal",
            "description": "Improper limitation of pathname",
            "risk": "High",
            "detection": "File operations with unsanitized user input",
            "code_patterns": ["new File(userInput)", "FileInputStream", "Paths.get"]
        },
        {
            "cwe_id": "CWE-611",
            "name": "XXE - XML External Entity",
            "description": "Improper restriction of XML external entity reference",
            "risk": "High",
            "detection": "XML parsing without disabling external entities",
            "code_patterns": ["DocumentBuilderFactory", "SAXParserFactory", "XMLReader"]
        },
        {
            "cwe_id": "CWE-327",
            "name": "Use of Broken Crypto",
            "description": "Use of weak cryptographic algorithms",
            "risk": "High",
            "detection": "MD5, SHA1, DES, or weak encryption",
            "code_patterns": ["MessageDigest.getInstance(\"MD5\")", "DES", "SHA1"]
        },
        {
            "cwe_id": "CWE-798",
            "name": "Hard-coded Credentials",
            "description": "Use of hard-coded credentials",
            "risk": "Critical",
            "detection": "Password or API key literals in code",
            "code_patterns": ["password = \"", "apiKey = \"", "secret = \""]
        },
        {
            "cwe_id": "CWE-306",
            "name": "Missing Authentication",
            "description": "Missing authentication for critical function",
            "risk": "Critical",
            "detection": "Sensitive operations without authentication checks",
            "code_patterns": ["@RequestMapping without security", "public methods"]
        },
        {
            "cwe_id": "CWE-863",
            "name": "Missing Authorization",
            "description": "Incorrect authorization",
            "risk": "High",
            "detection": "Protected resources without authorization checks",
            "code_patterns": ["missing @PreAuthorize", "no role check"]
        }
    ]
    
    for pattern in cwe_patterns:
        from brainary.memory.semantic import FactualKnowledge
        import uuid
        
        entry = FactualKnowledge(
            entry_id=f"cwe_{pattern['cwe_id']}_{uuid.uuid4().hex[:8]}",
            key_concepts=[pattern["name"], pattern["cwe_id"]],
            description=pattern["description"],
            entity=pattern["cwe_id"],
            properties=pattern,
            importance=0.9,
            metadata={"type": "cwe", "risk": pattern["risk"]}
        )
        memory.add_knowledge(entry)
    
    logger.info(f"Loaded {len(cwe_patterns)} CWE patterns")


def _load_remediation_templates(memory: SemanticMemory) -> None:
    """Load remediation templates as procedural knowledge."""
    remediation_templates = [
        {
            "vulnerability": "SQL Injection",
            "cwe_id": "CWE-89",
            "fix_pattern": "Use PreparedStatement with parameterized queries",
            "code_example": """// Secure approach
String query = "SELECT * FROM users WHERE id = ?";
PreparedStatement stmt = conn.prepareStatement(query);
stmt.setInt(1, userId);
ResultSet rs = stmt.executeQuery();""",
            "explanation": "PreparedStatements prevent SQL injection by separating SQL logic from data",
            "owasp_ref": "A03:2021 Injection"
        },
        {
            "vulnerability": "OS Command Injection",
            "cwe_id": "CWE-78",
            "fix_pattern": "Avoid Runtime.exec; use ProcessBuilder with validation",
            "code_example": """// Secure approach
ProcessBuilder pb = new ProcessBuilder("command", validatedArg);
pb.redirectErrorStream(true);
Process p = pb.start();""",
            "explanation": "Use ProcessBuilder with separate arguments and strict input validation",
            "owasp_ref": "A03:2021 Injection"
        },
        {
            "vulnerability": "XXE",
            "cwe_id": "CWE-611",
            "fix_pattern": "Disable external entities in XML parsers",
            "code_example": """// Secure configuration
DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
DocumentBuilder db = dbf.newDocumentBuilder();""",
            "explanation": "Explicitly disable external entity processing to prevent XXE attacks",
            "owasp_ref": "A05:2021 Security Misconfiguration"
        },
        {
            "vulnerability": "Weak Cryptography",
            "cwe_id": "CWE-327",
            "fix_pattern": "Use strong algorithms (SHA-256+, AES-256)",
            "code_example": """// Secure approach
MessageDigest digest = MessageDigest.getInstance("SHA-256");
Cipher cipher = Cipher.getInstance("AES/GCM/NoPadding");""",
            "explanation": "Use modern, secure cryptographic algorithms",
            "owasp_ref": "A02:2021 Cryptographic Failures"
        },
        {
            "vulnerability": "Hard-coded Credentials",
            "cwe_id": "CWE-798",
            "fix_pattern": "Store credentials in secure configuration",
            "code_example": """// Secure approach
String apiKey = System.getenv("API_KEY");
// Or use secure vault like AWS Secrets Manager
String password = vaultClient.getSecret("db-password");""",
            "explanation": "Never hard-code credentials; use environment variables or secure vaults",
            "owasp_ref": "A02:2021 Cryptographic Failures"
        },
        {
            "vulnerability": "Path Traversal",
            "cwe_id": "CWE-22",
            "fix_pattern": "Validate and canonicalize file paths",
            "code_example": """// Secure approach
Path basePath = Paths.get("/safe/directory");
Path requestedPath = basePath.resolve(userInput).normalize();
if (!requestedPath.startsWith(basePath)) {
    throw new SecurityException("Invalid path");
}
File file = requestedPath.toFile();""",
            "explanation": "Validate paths stay within allowed directory boundaries",
            "owasp_ref": "A01:2021 Broken Access Control"
        },
        {
            "vulnerability": "Insecure Deserialization",
            "cwe_id": "CWE-502",
            "fix_pattern": "Validate and use safe serialization formats",
            "code_example": """// Secure approach
// Prefer JSON or other safe formats
ObjectMapper mapper = new ObjectMapper();
MyObject obj = mapper.readValue(jsonString, MyObject.class);
// If using Java serialization, implement validateObject()""",
            "explanation": "Avoid Java serialization; use JSON/XML with schema validation",
            "owasp_ref": "A08:2021 Software and Data Integrity Failures"
        },
        {
            "vulnerability": "XSS",
            "cwe_id": "CWE-79",
            "fix_pattern": "Encode output and use Content Security Policy",
            "code_example": """// Secure approach
String encoded = StringEscapeUtils.escapeHtml4(userInput);
response.getWriter().write(encoded);
// Add CSP header
response.setHeader("Content-Security-Policy", "default-src 'self'");""",
            "explanation": "Always encode user input before rendering in HTML",
            "owasp_ref": "A03:2021 Injection"
        }
    ]
    
    for template in remediation_templates:
        from brainary.memory.semantic import ProceduralKnowledge
        import uuid
        
        entry = ProceduralKnowledge(
            entry_id=f"fix_{template['cwe_id']}_{uuid.uuid4().hex[:8]}",
            key_concepts=[template["vulnerability"], template["cwe_id"], "remediation", "fix"],
            description=template["fix_pattern"],
            procedure_type="remediation",
            implementation=template["code_example"],
            importance=0.85,
            metadata=template
        )
        memory.add_knowledge(entry)
    
    logger.info(f"Loaded {len(remediation_templates)} remediation templates")


def _load_detection_skills(memory: SemanticMemory) -> None:
    """Load detection skills and techniques."""
    detection_skills = [
        {
            "skill": "Static Pattern Matching",
            "description": "Identify vulnerabilities through code pattern recognition",
            "technique": "Use regex and AST analysis to find dangerous patterns",
            "effectiveness": "High for known patterns, limited for complex logic",
            "examples": ["Regex for SQL concatenation", "AST traversal for command injection"]
        },
        {
            "skill": "Data Flow Analysis",
            "description": "Track data flow from source to sink",
            "technique": "Trace user input through the application to sensitive operations",
            "effectiveness": "High for injection vulnerabilities",
            "examples": ["Taint analysis", "Source-to-sink tracing"]
        },
        {
            "skill": "Context-Aware Analysis",
            "description": "Consider code context and framework usage",
            "technique": "Understand framework security features and their usage",
            "effectiveness": "Reduces false positives significantly",
            "examples": ["Spring Security annotations", "Input validation frameworks"]
        },
        {
            "skill": "LLM-Powered Deep Analysis",
            "description": "Use language models for semantic understanding",
            "technique": "Leverage LLM to understand complex code logic and security implications",
            "effectiveness": "High for complex vulnerabilities and novel patterns",
            "examples": ["Business logic flaws", "Subtle authorization issues"]
        },
        {
            "skill": "False Positive Reduction",
            "description": "Filter out false positives through validation",
            "technique": "Apply heuristics and LLM reasoning to validate findings",
            "effectiveness": "Critical for production use",
            "examples": ["Mitigation detection", "Framework protection recognition"]
        }
    ]
    
    for skill in detection_skills:
        from brainary.memory.semantic import ProceduralKnowledge
        import uuid
        
        entry = ProceduralKnowledge(
            entry_id=f"skill_{uuid.uuid4().hex[:8]}",
            key_concepts=[skill["skill"], "detection", "technique"],
            description=skill["description"],
            procedure_type="detection_skill",
            implementation=skill["technique"],
            importance=0.8,
            metadata=skill
        )
        memory.add_knowledge(entry)
    
    logger.info(f"Loaded {len(detection_skills)} detection skills")


def get_vulnerability_context(semantic_memory: SemanticMemory, query: str, top_k: int = 5) -> List[Dict[str, Any]]:
    """
    Retrieve relevant vulnerability knowledge from semantic memory.
    
    Args:
        semantic_memory: SemanticMemory instance
        query: Search query (vulnerability type, CWE ID, etc.)
        top_k: Number of results to return
        
    Returns:
        List of relevant knowledge items
    """
    from brainary.memory.semantic import KnowledgeType
    
    # Search across all knowledge types
    results = []
    
    # Search factual knowledge (OWASP, CWE patterns)
    factual_results = semantic_memory.search(
        query=query, 
        knowledge_types=[KnowledgeType.FACTUAL], 
        top_k=top_k
    )
    results.extend([{"type": "factual", "content": item.properties} for item in factual_results])
    
    # Search procedural knowledge (remediation patterns)
    procedural_results = semantic_memory.search(
        query=query, 
        knowledge_types=[KnowledgeType.PROCEDURAL], 
        top_k=3
    )
    results.extend([{"type": "procedural", "content": item.metadata} for item in procedural_results])
    
    return results[:top_k]
