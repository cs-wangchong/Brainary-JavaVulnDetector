"""
Java Security Domain Primitives

Specialized primitives for vulnerability detection and security analysis.
"""

from typing import Any, Dict, List, Optional, Tuple
from brainary.primitive.base import CorePrimitive, PrimitiveResult, CostMetrics, ConfidenceScore, ResourceEstimate
from brainary.core.context import ExecutionContext
from brainary.memory.working import WorkingMemory

from .knowledge import VulnerabilityKnowledgeBase, VulnerabilityPattern
from .tools import SecurityScanner, ToolResult, ToolStatus


class ThinkSecurityPrimitive(CorePrimitive):
    """
    Security-focused reasoning primitive.
    
    Analyzes code from a security perspective, identifying potential
    vulnerabilities and attack vectors using LLM reasoning.
    """
    
    def __init__(self):
        super().__init__()
        self.kb = VulnerabilityKnowledgeBase()
    
    def validate_inputs(self, **kwargs) -> None:
        """Validate inputs for security analysis."""
        if 'code' not in kwargs or not kwargs['code']:
            raise ValueError("Code parameter is required and cannot be empty")
    
    def estimate_cost(self, **kwargs) -> ResourceEstimate:
        """Estimate cost based on code length."""
        code = kwargs.get('code', '') or kwargs.get('code_context', '')
        code_lines = len(code.split('\n'))
        # Estimate ~10 tokens per line, plus 500 for prompts
        estimated_tokens = (code_lines * 10) + 500
        return ResourceEstimate(
            tokens=estimated_tokens,
            time_ms=2000,  # ~2 seconds for LLM call
            memory_items=1,
            llm_calls=1,
            complexity=0.6,
            confidence=0.8
        )
    
    def rollback(self, context: ExecutionContext) -> None:
        """No side effects to rollback for read-only analysis."""
        pass
    
    def execute(self, context: ExecutionContext, working_memory: WorkingMemory, **kwargs) -> PrimitiveResult:
        """
        Think about security implications of code.
        
        Args:
            context: Execution context
            memory: Working memory
            **kwargs: Parameters including 'code' and optional 'focus'
        
        Returns:
            PrimitiveResult with security analysis
        """
        # Extract parameters
        code = kwargs.get('code') or kwargs.get('code_context', '')
        focus = kwargs.get('focus')
        # Build prompt for security analysis
        system_prompt = """You are a security expert specializing in Java vulnerability detection.
Analyze code for security vulnerabilities, focusing on OWASP Top 10 and common CWE patterns.

For each potential vulnerability:
1. Identify the specific CWE/OWASP category
2. Explain why it's vulnerable
3. Assess the severity and exploitability
4. Suggest specific remediation
"""
        
        # Add focus-specific guidance
        if focus:
            patterns = self.kb.search(focus)
            if patterns:
                system_prompt += f"\n\nFocus on these vulnerability types:\n"
                for pattern in patterns[:3]:
                    system_prompt += f"- {pattern.name} ({pattern.cwe_id}): {pattern.description}\n"
        
        user_prompt = f"""Analyze this Java code for security vulnerabilities:

```java
{code}
```

Provide a detailed security analysis including:
1. Identified vulnerabilities (with CWE IDs)
2. Severity assessment
3. Attack scenarios
4. Remediation recommendations
"""
        
        # Use LLM for intelligent security analysis
        try:
            from brainary.llm.manager import get_llm_manager
            
            llm_manager = get_llm_manager()
            
            # Build messages for LLM
            messages = [
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_prompt}
            ]
            
            # Request LLM analysis
            llm_response = llm_manager.request(
                messages=messages,
                temperature=0.3,  # Lower temperature for more focused security analysis
                max_tokens=2000
            )
            
            response = llm_response.content
            
            # Parse LLM response for structured data
            analysis = self._parse_security_analysis(response)
            
        except Exception as e:
            # Fallback to pattern-based analysis if LLM unavailable
            import logging
            logging.getLogger(__name__).error(f"LLM analysis failed, using pattern-based fallback: {e}")
            
            # Provide basic pattern-based analysis
            response = f"Security analysis of code (length: {len(code)} chars)\n\n"
            response += "⚠️ Note: LLM analysis unavailable, using pattern-based detection.\n\n"
            
            # Basic vulnerability detection
            if "DocumentBuilderFactory" in code and "setFeature" not in code:
                response += "• Potential XXE vulnerability: XML parsing without security features\n"
            if "ObjectInputStream" in code:
                response += "• Insecure deserialization detected\n"
            if "Runtime.getRuntime().exec" in code or "ProcessBuilder" in code:
                response += "• Command execution detected - potential injection risk\n"
            if "Logger" in code and "info" in code:
                response += "• Logging user input - check for Log4Shell vulnerability\n"
                
            if focus:
                response += f"\nFocus area: {focus}\n"
            
            # Parse analysis from response
            analysis = self._parse_security_analysis(response)
        
        return PrimitiveResult(
            content=response,
            confidence=ConfidenceScore(overall=0.7, reasoning=0.7),
            execution_mode=context.execution_mode,
            cost=CostMetrics(tokens=500, latency_ms=2000, memory_slots=1, provider_cost_usd=0.01),
            primitive_name="think_security",
            success=True,
            metadata={
                "vulnerabilities": analysis.get("vulnerabilities", []),
                "focus": focus,
                "severity_counts": analysis.get("severity_counts", {}),
                "note": "Simplified analysis without LLM integration"
            }
        )
    
    def _parse_security_analysis(self, response: str) -> Dict[str, Any]:
        """Parse LLM response into structured analysis"""
        # Simple parsing - extract CWE mentions
        import re
        
        vulnerabilities = []
        cwe_pattern = re.compile(r'CWE-\d+')
        
        for match in cwe_pattern.finditer(response):
            cwe_id = match.group(0)
            pattern = self.kb.get_pattern(cwe_id)
            if pattern:
                vulnerabilities.append({
                    "cwe_id": cwe_id,
                    "name": pattern.name,
                    "severity": pattern.severity.value
                })
        
        # Count severities
        severity_counts = {}
        for vuln in vulnerabilities:
            severity = vuln["severity"]
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        return {
            "vulnerabilities": vulnerabilities,
            "severity_counts": severity_counts
        }


class AnalyzeCodePrimitive(CorePrimitive):
    """
    Code analysis primitive combining static analysis and LLM insights.
    
    Uses security tools (CodeQL, pattern matching) and LLM reasoning
    for comprehensive analysis.
    """
    
    def __init__(self):
        super().__init__()
        self.scanner = SecurityScanner(use_codeql=False)  # Pattern-based for speed
    
    def validate_inputs(self, **kwargs) -> None:
        """Validate inputs for code analysis."""
        if 'target' not in kwargs or not kwargs['target']:
            raise ValueError("Target parameter is required")
    
    def estimate_cost(self, **kwargs) -> ResourceEstimate:
        """Estimate cost for code analysis."""
        deep_analysis = kwargs.get('deep_analysis', False)
        tokens = 5000 if deep_analysis else 100  # LLM tokens if deep, minimal otherwise
        return ResourceEstimate(
            tokens=tokens,
            time_ms=3000 if deep_analysis else 500,
            memory_items=1,
            llm_calls=1 if deep_analysis else 0,
            complexity=0.7 if deep_analysis else 0.3,
            confidence=0.8
        )
    
    def rollback(self, context: ExecutionContext) -> None:
        """No side effects to rollback."""
        pass
    
    def execute(self, context: ExecutionContext, working_memory,
                **kwargs) -> PrimitiveResult:
        """
        Analyze code for vulnerabilities.
        
        Args:
            context: Execution context
            memory: Working memory
            **kwargs: Must include 'target', optional 'deep_analysis'
        
        Returns:
            PrimitiveResult with analysis results
        """
        target = kwargs.get('target')
        deep_analysis = kwargs.get('deep_analysis', False)
        # Run static analysis
        scan_results = self.scanner.scan(target, use_codeql=False, use_patterns=True)
        
        # Extract findings
        all_findings = []
        for tool_result in scan_results.values():
            if tool_result.status == ToolStatus.SUCCESS:
                all_findings.extend(tool_result.findings)
        
        # If deep analysis requested, use LLM for validation
        if deep_analysis and all_findings:
            validated_findings = self._validate_with_llm(context, all_findings[:5])
            
            return PrimitiveResult(
                content=f"Found {len(all_findings)} potential issues, validated {len(validated_findings)}",
                confidence=ConfidenceScore(overall=0.85, reasoning=0.8),
                execution_mode=context.execution_mode,
                cost=CostMetrics(tokens=800, latency_ms=3000, memory_slots=len(all_findings), provider_cost_usd=0.015),
                primitive_name="analyze_code",
                success=True,
                metadata={
                    "findings": all_findings,
                    "validated": validated_findings,
                    "scan_results": {k: {"status": v.status.value, "count": len(v.findings)} 
                                    for k, v in scan_results.items()}
                }
            )
        else:
            return PrimitiveResult(
                content=f"Found {len(all_findings)} potential issues",
                confidence=ConfidenceScore(overall=0.7, reasoning=0.7),
                execution_mode=context.execution_mode,
                cost=CostMetrics(tokens=500, latency_ms=2000, memory_slots=len(all_findings), provider_cost_usd=0.01),
                primitive_name="analyze_code",
                success=True,
                metadata={
                    "findings": all_findings,
                    "scan_results": {k: {"status": v.status.value, "count": len(v.findings)} 
                                    for k, v in scan_results.items()}
                }
            )
    
    def _validate_with_llm(self, context: ExecutionContext, 
                          findings: List[Dict]) -> List[Dict]:
        """Use LLM to validate findings and reduce false positives"""
        validated = []
        
        for finding in findings:
            # Build validation prompt
            system_prompt = "You are a security expert. Validate if this is a true vulnerability or false positive."
            
            user_prompt = f"""
Pattern detected: {finding.get('pattern', 'unknown')}
File: {finding.get('file', 'unknown')}
Line: {finding.get('line', 0)}
Match: {finding.get('match', '')}

Context:
{finding.get('context', '')}

Is this a true vulnerability or false positive? Explain briefly.
"""
            
            messages = self.construct_conversation(
                context,
                system_message=system_prompt,
                user_message=user_prompt
            )
            
            response = context.execute_llm(messages)
            
            # Simple validation - check if LLM confirms vulnerability
            if "true vulnerability" in response.lower() or "vulnerable" in response.lower():
                finding["validation"] = response
                finding["confirmed"] = True
                validated.append(finding)
        
        return validated


class DetectVulnerabilityPrimitive(CorePrimitive):
    """
    Specialized vulnerability detection primitive.
    
    Focuses on specific vulnerability types using knowledge base
    and targeted detection strategies.
    """
    
    def __init__(self):
        super().__init__()
        self.kb = VulnerabilityKnowledgeBase()
    
    def validate_inputs(self, **kwargs) -> None:
        """Validate inputs for vulnerability detection."""
        if 'code' not in kwargs or not kwargs['code']:
            raise ValueError("Code parameter is required")
    
    def estimate_cost(self, **kwargs) -> ResourceEstimate:
        """Estimate cost for vulnerability detection."""
        code = kwargs.get('code', '')
        code_lines = len(code.split('\n'))
        estimated_tokens = (code_lines * 10) + 800
        return ResourceEstimate(
            tokens=estimated_tokens,
            time_ms=2500,
            memory_items=1,
            llm_calls=1,
            complexity=0.6,
            confidence=0.8
        )
    
    def rollback(self, context: ExecutionContext) -> None:
        """No side effects to rollback."""
        pass
    
    def execute(self, context: ExecutionContext, working_memory,
                **kwargs) -> PrimitiveResult:
        """
        Detect specific vulnerability types.
        
        Args:
            context: Execution context
            memory: Working memory
            **kwargs: Must include 'code', optional 'vulnerability_types'
        
        Returns:
            PrimitiveResult with detections
        """
        code = kwargs.get('code')
        vulnerability_types = kwargs.get('vulnerability_types')
        # Get patterns to check
        patterns_to_check = []
        if vulnerability_types:
            for vuln_type in vulnerability_types:
                if vuln_type.startswith("CWE-"):
                    pattern = self.kb.get_pattern(vuln_type)
                    if pattern:
                        patterns_to_check.append(pattern)
                else:
                    # Search by name/category
                    patterns_to_check.extend(self.kb.search(vuln_type))
        else:
            # Check all high/critical severity patterns
            from .knowledge import VulnerabilitySeverity
            patterns_to_check.extend(self.kb.get_by_severity(VulnerabilitySeverity.CRITICAL))
            patterns_to_check.extend(self.kb.get_by_severity(VulnerabilitySeverity.HIGH))
        
        # Build detection prompt
        system_prompt = """You are a vulnerability detection expert.
Analyze the code and determine if it contains the specified vulnerabilities.
Be precise and avoid false positives."""
        
        vulnerability_descriptions = "\n".join([
            f"- {p.cwe_id} ({p.name}): {p.description}\n  Indicators: {', '.join(p.indicators[:3])}"
            for p in patterns_to_check[:5]
        ])
        
        user_prompt = f"""Check for these vulnerabilities:

{vulnerability_descriptions}

Code to analyze:
```java
{code}
```

For each vulnerability found:
1. State the CWE ID and name
2. Point to the vulnerable code
3. Explain why it's vulnerable
4. Rate confidence (high/medium/low)
"""
        
        messages = self.construct_conversation(
            context,
            system_message=system_prompt,
            user_message=user_prompt
        )
        
        response = context.execute_llm(messages)
        
        # Parse detections
        detections = self._parse_detections(response, patterns_to_check)
        
        return PrimitiveResult(
            content=response,
            confidence=ConfidenceScore(overall=0.8, reasoning=0.75),
            execution_mode=context.execution_mode,
            cost=CostMetrics(tokens=400, latency_ms=1500, memory_slots=1, provider_cost_usd=0.008),
            primitive_name="detect_vulnerability",
            success=True,
            metadata={
                "detections": detections,
                "patterns_checked": [p.cwe_id for p in patterns_to_check]
            }
        )
    
    def _parse_detections(self, response: str, 
                         patterns: List[VulnerabilityPattern]) -> List[Dict]:
        """Parse LLM response into structured detections"""
        import re
        
        detections = []
        
        # Extract CWE mentions with confidence
        for pattern in patterns:
            if pattern.cwe_id in response:
                # Try to extract confidence
                confidence = "medium"
                if "high confidence" in response.lower():
                    confidence = "high"
                elif "low confidence" in response.lower():
                    confidence = "low"
                
                detections.append({
                    "cwe_id": pattern.cwe_id,
                    "name": pattern.name,
                    "severity": pattern.severity.value,
                    "confidence": confidence,
                    "pattern": pattern
                })
        
        return detections


class ValidateFindingPrimitive(CorePrimitive):
    """
    Validation primitive for verifying vulnerability findings.
    
    Performs deep analysis to confirm vulnerabilities and eliminate
    false positives using multi-perspective reasoning.
    """
    
    def __init__(self):
        super().__init__()
        self.kb = VulnerabilityKnowledgeBase()
    
    def validate_inputs(self, **kwargs) -> None:
        """Validate inputs for finding validation."""
        if 'finding' not in kwargs or not kwargs['finding']:
            raise ValueError("Finding parameter is required")
        if 'code_context' not in kwargs:
            raise ValueError("Code context parameter is required")
    
    def estimate_cost(self, **kwargs) -> ResourceEstimate:
        """Estimate cost for validation."""
        code_context = kwargs.get('code_context', '')
        estimated_tokens = len(code_context.split()) * 1.3 + 1000
        return ResourceEstimate(
            tokens=int(estimated_tokens),
            time_ms=2000,
            memory_items=1,
            llm_calls=1,
            complexity=0.6,
            confidence=0.8
        )
    
    def rollback(self, context: ExecutionContext) -> None:
        """No side effects to rollback."""
        pass
    
    def execute(self, context: ExecutionContext, working_memory,
                **kwargs) -> PrimitiveResult:
        """
        Validate a vulnerability finding.
        
        Args:
            context: Execution context
            memory: Working memory
            **kwargs: Must include 'finding' and 'code_context'
        
        Returns:
            PrimitiveResult with validation result
        """
        finding = kwargs.get('finding')
        code_context = kwargs.get('code_context')
        cwe_id = finding.get("cwe_id", "")
        pattern = self.kb.get_pattern(cwe_id)
        
        if not pattern:
            return PrimitiveResult(
                content="Unknown vulnerability type",
                confidence=ConfidenceScore(overall=0.0, reasoning=0.0),
                execution_mode=context.execution_mode,
                cost=CostMetrics(tokens=0, latency_ms=10.0, memory_slots=0, provider_cost_usd=0.0),
                primitive_name="validate_finding",
                success=False,
                metadata={"valid": False, "reason": "Unknown CWE"}
            )
        
        # Build validation prompt with detailed checks
        system_prompt = f"""You are a security validation expert.
Validate if this is a TRUE VULNERABILITY or FALSE POSITIVE.

Vulnerability Type: {pattern.name} ({pattern.cwe_id})
Description: {pattern.description}

False Positive Checks:
{chr(10).join('- ' + check for check in pattern.false_positive_checks)}

Be thorough and consider:
1. Is user input actually involved?
2. Are there mitigating controls?
3. Is the vulnerable code actually reachable?
4. Does the context make it exploitable?
"""
        
        user_prompt = f"""
Finding: {finding.get('message', 'Potential vulnerability detected')}
Location: {finding.get('file', 'unknown')} line {finding.get('line', 0)}

Code Context:
```java
{code_context}
```

Is this a TRUE VULNERABILITY or FALSE POSITIVE?

Provide:
1. Verdict (TRUE VULNERABILITY / FALSE POSITIVE)
2. Confidence level (high/medium/low)
3. Reasoning
4. If true vulnerability: exploitability assessment
5. If false positive: what mitigates it
"""
        
        try:
            messages = self.construct_conversation(
                context,
                system_message=system_prompt,
                user_message=user_prompt
            )
            
            response = context.execute_llm(messages)
        except Exception as e:
            # LLM execution failed - return error
            import logging
            logging.getLogger(__name__).error(f"LLM validation failed: {e}")
            return PrimitiveResult(
                content=f"Validation failed: {str(e)}",
                confidence=ConfidenceScore(overall=0.0, reasoning=0.0),
                execution_mode=context.execution_mode,
                cost=CostMetrics(tokens=0, latency_ms=100, memory_slots=0, provider_cost_usd=0.0),
                primitive_name="validate_finding",
                success=False,
                metadata={"valid": None, "error": str(e)}
            )
        
        # Parse validation result - more robust parsing
        response_lower = response.lower()
        
        # Look for explicit verdicts first
        if "verdict:" in response_lower:
            verdict_section = response_lower.split("verdict:")[1].split("\n")[0]
            is_valid = "true vulnerability" in verdict_section and "false positive" not in verdict_section
        elif "false positive" in response_lower and "not a false positive" not in response_lower:
            is_valid = False
        elif "true vulnerability" in response_lower and "not a true vulnerability" not in response_lower:
            is_valid = True  
        else:
            # Default to valid if unclear (conservative approach for security)
            is_valid = True
            
        confidence_str = self._extract_confidence(response)
        
        # Map string confidence to numeric
        confidence_map = {"high": 0.9, "medium": 0.7, "low": 0.5}
        confidence_val = confidence_map.get(confidence_str, 0.7)
        
        return PrimitiveResult(
            content=response,
            confidence=ConfidenceScore(overall=confidence_val, reasoning=confidence_val),
            execution_mode=context.execution_mode,
            cost=CostMetrics(tokens=300, latency_ms=1000, memory_slots=1, provider_cost_usd=0.006),
            primitive_name="validate_finding",
            success=True,
            metadata={
                "valid": is_valid,
                "confidence": confidence_str,
                "cwe_id": cwe_id,
                "finding": finding
            }
        )
    
    def _extract_confidence(self, response: str) -> str:
        """Extract confidence level from response"""
        response_lower = response.lower()
        if "high confidence" in response_lower or "confidence: high" in response_lower:
            return "high"
        elif "low confidence" in response_lower or "confidence: low" in response_lower:
            return "low"
        else:
            return "medium"


class RecommendFixPrimitive(CorePrimitive):
    """
    Fix recommendation primitive.
    
    Provides specific, actionable remediation guidance for vulnerabilities.
    """
    
    def __init__(self):
        super().__init__()
        self.kb = VulnerabilityKnowledgeBase()
    
    def validate_inputs(self, **kwargs) -> None:
        """Validate inputs for fix recommendation."""
        if 'vulnerability' not in kwargs or not kwargs['vulnerability']:
            raise ValueError("Vulnerability parameter is required")
        if 'code' not in kwargs or not kwargs['code']:
            raise ValueError("Code parameter is required")
    
    def estimate_cost(self, **kwargs) -> ResourceEstimate:
        """Estimate cost for fix recommendation."""
        code = kwargs.get('code', '')
        estimated_tokens = len(code.split()) * 1.5 + 1200
        return ResourceEstimate(
            tokens=int(estimated_tokens),
            time_ms=2500,
            memory_items=1,
            llm_calls=1,
            complexity=0.7,
            confidence=0.8
        )
    
    def rollback(self, context: ExecutionContext) -> None:
        """No side effects to rollback."""
        pass
    
    def execute(self, context: ExecutionContext, working_memory,
                **kwargs) -> PrimitiveResult:
        """
        Recommend fix for vulnerability.
        
        Args:
            context: Execution context
            memory: Working memory
            **kwargs: Must include 'vulnerability' and 'code'
        
        Returns:
            PrimitiveResult with fix recommendations
        """
        vulnerability = kwargs.get('vulnerability')
        code = kwargs.get('code')
        cwe_id = vulnerability.get("cwe_id", "")
        pattern = self.kb.get_pattern(cwe_id)
        
        if not pattern:
            return PrimitiveResult(
                content="Cannot recommend fix for unknown vulnerability",
                confidence=ConfidenceScore(overall=0.0, reasoning=0.0),
                execution_mode=context.execution_mode,
                cost=CostMetrics(tokens=0, latency_ms=10.0, memory_slots=0, provider_cost_usd=0.0),
                primitive_name="recommend_fix",
                success=False,
                metadata={"has_fix": False}
            )
        
        # Build fix recommendation prompt
        system_prompt = f"""You are a security remediation expert.
Provide specific, actionable fixes for {pattern.name} ({pattern.cwe_id}).

General Remediation: {pattern.remediation}

Secure Alternatives:
{chr(10).join('- ' + alt for alt in pattern.secure_alternatives)}

Secure Example:
{pattern.secure_example}
"""
        
        user_prompt = f"""
Vulnerable Code:
```java
{code}
```

Provide a SPECIFIC FIX for this code:
1. Exact code changes needed
2. Line-by-line transformation
3. Additional security measures
4. Testing recommendations

Be concrete and actionable.
"""
        
        messages = self.construct_conversation(
            context,
            system_message=system_prompt,
            user_message=user_prompt
        )
        
        response = context.execute_llm(messages)
        
        return PrimitiveResult(
            content=response,
            confidence=ConfidenceScore(overall=0.8, reasoning=0.85),
            execution_mode=context.execution_mode,
            cost=CostMetrics(tokens=600, latency_ms=2500, memory_slots=1, provider_cost_usd=0.012),
            primitive_name="recommend_fix",
            success=True,
            metadata={
                "has_fix": True,
                "cwe_id": cwe_id,
                "pattern": pattern.name,
                "secure_alternatives": pattern.secure_alternatives
            }
        )
