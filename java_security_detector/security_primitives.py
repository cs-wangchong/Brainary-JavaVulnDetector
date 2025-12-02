"""
Security Domain-Specific Primitives

Custom primitives for Java vulnerability detection using Brainary SDK.
These primitives extend CorePrimitive with security-specific logic and LLM integration.
"""

from typing import Any, Dict, List, Optional
import re
import logging
from pathlib import Path

from brainary.primitive.base import CorePrimitive, PrimitiveResult, ResourceEstimate, CostMetrics, ConfidenceMetrics
from brainary.core.context import ExecutionContext
from brainary.memory.working import WorkingMemory
from brainary.memory.semantic import SemanticMemory
import time

from .knowledge import VulnerabilityKnowledgeBase
from .tools import SecurityScanner, ToolStatus

logger = logging.getLogger(__name__)


def create_result(
    content: Any,
    confidence: float,
    metadata: Dict[str, Any],
    context: ExecutionContext,
    success: bool = True,
    start_time: Optional[float] = None,
    tokens: int = 0,
    primitive_name: str = "security_primitive"
) -> PrimitiveResult:
    """Helper to create PrimitiveResult with required fields."""
    execution_time = int((time.time() - start_time) * 1000) if start_time else 0
    
    return PrimitiveResult(
        content=content,
        confidence=ConfidenceMetrics(
            overall=confidence,
            reasoning=confidence,
            completeness=confidence,
            consistency=confidence,
            evidence_strength=confidence
        ),
        execution_mode=context.execution_mode,
        cost=CostMetrics(
            tokens=tokens,
            latency_ms=execution_time,
            memory_slots=1,
            provider_cost_usd=0.0
        ),
        metadata=metadata,
        primitive_name=primitive_name,
        success=success
    )


class ScanCodePrimitive(CorePrimitive):
    """
    Primitive for scanning Java code for potential vulnerabilities.
    
    Uses pattern matching and static analysis to identify suspicious code patterns.
    """
    
    def __init__(self):
        super().__init__()
        self.scanner = SecurityScanner(use_codeql=False)
        self.kb = VulnerabilityKnowledgeBase()
    
    def validate_inputs(self, **kwargs) -> None:
        """Validate scan inputs."""
        if 'target' not in kwargs or not kwargs['target']:
            raise ValueError("Target file/directory is required")
    
    def estimate_cost(self, **kwargs) -> ResourceEstimate:
        """Estimate scanning cost based on target size."""
        target = kwargs.get('target', '')
        target_path = Path(target)
        
        # Estimate file count for directories
        if target_path.is_dir():
            java_files = list(target_path.rglob("*.java"))
            file_count = len(java_files)
        else:
            file_count = 1
        
        return ResourceEstimate(
            tokens=100 * file_count,  # Pattern matching uses minimal tokens
            time_ms=500 * file_count,
            memory_items=file_count,
            llm_calls=0,  # No LLM for pattern scanning
            complexity=0.3,
            confidence=0.9
        )
    
    def rollback(self, context: ExecutionContext) -> None:
        """No side effects to rollback (read-only operation)."""
        pass
    
    def execute(self, context: ExecutionContext, working_memory: WorkingMemory, 
                **kwargs) -> PrimitiveResult:
        """
        Scan code for potential vulnerabilities.
        
        Args:
            target: File or directory path to scan
            use_patterns: Whether to use pattern matching (default: True)
            
        Returns:
            PrimitiveResult with findings list
        """
        start_time = time.time()
        target = kwargs.get('target')
        use_patterns = kwargs.get('use_patterns', True)
        
        logger.info(f"Scanning {target} for vulnerabilities")
        
        try:
            # Run security scanner
            scan_results = self.scanner.scan(target, use_codeql=False, use_patterns=use_patterns)
            
            # Collect findings from all tools
            all_findings = []
            for tool_name, tool_result in scan_results.items():
                if tool_result.status == ToolStatus.SUCCESS:
                    all_findings.extend(tool_result.findings)
            
            # Store findings in working memory
            working_memory.store(
                content={
                    "action": "scan",
                    "target": target,
                    "findings_count": len(all_findings),
                    "tools_used": list(scan_results.keys())
                },
                importance=0.8,
                tags=["scan", "findings"]
            )
            
            logger.info(f"Scan complete: {len(all_findings)} potential issues found")
            
            return create_result(
                content={
                    "findings": all_findings,
                    "findings_count": len(all_findings),
                    "target": target,
                    "tools": list(scan_results.keys())
                },
                confidence=0.8,
                metadata={
                    "primitive": "scan_code",
                    "tools_count": len(scan_results)
                },
                context=context,
                success=True,
                start_time=start_time,
                primitive_name="scan_code"
            )
        
        except Exception as e:
            logger.error(f"Scan failed: {e}")
            return create_result(
                content={"error": str(e)},
                confidence=0.0,
                metadata={"primitive": "scan_code", "error_type": type(e).__name__},
                context=context,
                success=False,
                start_time=start_time,
                primitive_name="scan_code"
            )
class AnalyzeVulnerabilityPrimitive(CorePrimitive):
    """
    LLM-powered primitive for deep vulnerability analysis.
    
    Uses semantic memory to enhance analysis with known patterns and context.
    """
    
    def __init__(self):
        super().__init__()
        self.kb = VulnerabilityKnowledgeBase()
    
    def validate_inputs(self, **kwargs) -> None:
        """Validate analysis inputs."""
        if 'code' not in kwargs or not kwargs['code']:
            raise ValueError("Code snippet is required for analysis")
    
    def estimate_cost(self, **kwargs) -> ResourceEstimate:
        """Estimate analysis cost."""
        code = kwargs.get('code', '')
        code_lines = len(code.split('\n'))
        estimated_tokens = (code_lines * 15) + 800  # Code + prompt
        
        return ResourceEstimate(
            tokens=estimated_tokens,
            time_ms=3000,  # LLM latency
            memory_items=1,
            llm_calls=1,
            complexity=0.7,
            confidence=0.85
        )
    
    def rollback(self, context: ExecutionContext) -> None:
        """No side effects to rollback."""
        pass
    
    def execute(self, context: ExecutionContext, working_memory: WorkingMemory,
                semantic_memory: Optional[SemanticMemory] = None, **kwargs) -> PrimitiveResult:
        """
        Analyze code for security vulnerabilities using LLM.
        
        Args:
            code: Code snippet to analyze
            vulnerability_type: Optional hint about vulnerability type
            file_path: Optional file path for context
            
        Returns:
            PrimitiveResult with detailed analysis
        """
        start_time = time.time()
        code = kwargs.get('code')
        vuln_type = kwargs.get('vulnerability_type', '')
        file_path = kwargs.get('file_path', 'unknown')
        
        logger.info(f"Analyzing code from {file_path}")
        
        # Search semantic memory for related patterns
        knowledge_context = ""
        if semantic_memory and vuln_type:
            # Search semantic knowledge about this vulnerability type
            from brainary.memory.semantic import KnowledgeType
            related_knowledge = semantic_memory.search(
                query=vuln_type,
                knowledge_types=[KnowledgeType.FACTUAL],
                top_k=3
            )
            if related_knowledge:
                knowledge_context = "\n\nRelevant security knowledge:\n"
                for item in related_knowledge:
                    knowledge_context += f"- {item.description}\n"
        
        # Build LLM prompt
        system_prompt = """You are an expert security analyst specializing in Java vulnerability detection.
Analyze code for security issues following OWASP Top 10 and CWE standards.

For each vulnerability found, provide:
1. CWE ID and vulnerability name
2. Severity (Critical/High/Medium/Low)
3. Detailed explanation of the vulnerability
4. Potential attack scenarios
5. Exploitability assessment
6. Impact analysis

Be precise and security-focused in your analysis."""

        user_prompt = f"""Analyze this Java code for security vulnerabilities:

File: {file_path}
{f"Focus: {vuln_type}" if vuln_type else ""}

```java
{code}
```
{knowledge_context}

Provide detailed security analysis in JSON format:
{{
  "vulnerabilities": [
    {{
      "cwe_id": "CWE-XXX",
      "name": "Vulnerability Name",
      "severity": "High/Medium/Low",
      "description": "Detailed explanation",
      "attack_scenario": "How it could be exploited",
      "impact": "Potential consequences",
      "confidence": "High/Medium/Low"
    }}
  ],
  "overall_risk": "Assessment of overall risk",
  "notes": "Additional observations"
}}"""

        try:
            from brainary.llm.manager import get_llm_manager
            
            llm_manager = get_llm_manager()
            response = llm_manager.request(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                provider="openai",
                model="gpt-4o-mini",
                temperature=0.3,  # Lower temperature for consistent security analysis
                max_tokens=2000
            )
            
            # Parse response
            analysis_text = response.content
            
            # Try to extract JSON
            import json
            json_match = re.search(r'\{.*\}', analysis_text, re.DOTALL)
            if json_match:
                analysis = json.loads(json_match.group())
            else:
                # Fallback: return raw text
                analysis = {"raw_analysis": analysis_text, "vulnerabilities": []}
            
            # Store analysis in working memory
            working_memory.store(
                content={
                    "action": "analyze",
                    "file": file_path,
                    "vulnerabilities_found": len(analysis.get('vulnerabilities', [])),
                    "risk": analysis.get('overall_risk', 'unknown')
                },
                importance=0.9,
                tags=["analysis", "vulnerability"]
            )
            
            logger.info(f"Analysis complete: {len(analysis.get('vulnerabilities', []))} vulnerabilities identified")
            
            return create_result(
                content=analysis,
                confidence=0.85,
                metadata={
                    "primitive": "analyze_vulnerability",
                    "file_path": file_path,
                    "llm_model": "gpt-4o-mini",
                    "tokens_used": response.usage.total_tokens if hasattr(response, 'usage') else 0
                },
                context=context,
                success=True,
                start_time=start_time,
                tokens=response.usage.total_tokens if hasattr(response, 'usage') else 0,
                primitive_name="analyze_vulnerability"
            )
            
        except Exception as e:
            logger.error(f"Analysis failed: {e}")
            return create_result(
                content={"error": str(e), "code": code[:200]},
                confidence=0.0,
                metadata={"primitive": "analyze_vulnerability", "error_type": type(e).__name__},
                context=context,
                success=False,
                start_time=start_time,
                primitive_name="analyze_vulnerability"
            )


class ValidateFindingPrimitive(CorePrimitive):
    """
    Primitive for validating vulnerability findings to reduce false positives.
    
    Uses LLM reasoning and heuristics to assess finding validity.
    """
    
    def __init__(self):
        super().__init__()
    
    def validate_inputs(self, **kwargs) -> None:
        """Validate inputs."""
        if 'finding' not in kwargs:
            raise ValueError("Finding to validate is required")
    
    def estimate_cost(self, **kwargs) -> ResourceEstimate:
        """Estimate validation cost."""
        return ResourceEstimate(
            tokens=600,
            time_ms=2000,
            memory_items=1,
            llm_calls=1,
            complexity=0.5,
            confidence=0.8
        )
    
    def rollback(self, context: ExecutionContext) -> None:
        """No side effects to rollback."""
        pass
    
    def execute(self, context: ExecutionContext, working_memory: WorkingMemory,
                **kwargs) -> PrimitiveResult:
        """
        Validate a vulnerability finding.
        
        Args:
            finding: Finding dict with vulnerability details
            code_context: Optional broader code context
            
        Returns:
            PrimitiveResult with validation assessment
        """
        start_time = time.time()
        finding = kwargs.get('finding')
        code_context = kwargs.get('code_context', '')
        
        logger.info(f"Validating finding: {finding.get('name', 'unknown')}")
        
        # Build validation prompt
        system_prompt = """You are a security expert validating vulnerability findings.
Your job is to assess whether a reported vulnerability is:
1. A true positive (real vulnerability)
2. A false positive (not actually vulnerable)
3. Uncertain (needs more investigation)

Consider:
- Actual exploitability
- Presence of mitigations
- Context and data flow
- Coding patterns and frameworks used"""

        finding_desc = f"""CWE: {finding.get('cwe_id', 'N/A')}
Name: {finding.get('name', 'Unknown')}
Severity: {finding.get('severity', 'Unknown')}
Description: {finding.get('description', 'N/A')}

Code:
{finding.get('code', 'N/A')}
"""

        user_prompt = f"""Validate this security finding:

{finding_desc}

Assess:
1. Is this a true positive or false positive?
2. What is your confidence level (High/Medium/Low)?
3. What additional evidence supports or refutes this finding?
4. What is the actual exploitability?

Respond in JSON format:
{{
  "is_valid": true/false,
  "confidence": "High/Medium/Low",
  "reasoning": "Detailed explanation",
  "exploitability": "High/Medium/Low/None",
  "recommendation": "Keep/Dismiss/Investigate"
}}"""

        try:
            from brainary.llm.manager import get_llm_manager
            
            llm_manager = get_llm_manager()
            response = llm_manager.request(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                provider="openai",
                model="gpt-4o-mini",
                temperature=0.2,
                max_tokens=800
            )
            
            # Parse validation result
            import json
            validation_text = response.content
            json_match = re.search(r'\{.*\}', validation_text, re.DOTALL)
            
            if json_match:
                validation = json.loads(json_match.group())
            else:
                validation = {
                    "is_valid": True,
                    "confidence": "Medium",
                    "reasoning": validation_text,
                    "recommendation": "Investigate"
                }
            
            # Store validation in working memory
            working_memory.store(
                content={
                    "action": "validate",
                    "finding": finding.get('name', 'unknown'),
                    "is_valid": validation.get('is_valid'),
                    "confidence": validation.get('confidence')
                },
                importance=0.7,
                tags=["validation"]
            )
            
            logger.info(f"Validation complete: {validation.get('recommendation')}")
            
            return create_result(
                content=validation,
                confidence=0.8,
                metadata={
                    "primitive": "validate_finding",
                    "finding_name": finding.get('name', 'unknown')
                },
                context=context,
                success=True,
                start_time=start_time,
                primitive_name="validate_finding"
            )
            
        except Exception as e:
            logger.error(f"Validation failed: {e}")
            return create_result(
                content={"error": str(e), "is_valid": True},  # Default to keeping finding
                confidence=0.0,
                metadata={"primitive": "validate_finding", "error_type": type(e).__name__},
                context=context,
                success=False,
                start_time=start_time,
                primitive_name="validate_finding"
            )


class RecommendFixPrimitive(CorePrimitive):
    """
    Primitive for generating fix recommendations for vulnerabilities.
    
    Uses LLM and procedural memory to suggest secure code patterns.
    """
    
    def __init__(self):
        super().__init__()
    
    def validate_inputs(self, **kwargs) -> None:
        """Validate inputs."""
        if 'vulnerability' not in kwargs:
            raise ValueError("Vulnerability details required")
        if 'code' not in kwargs:
            raise ValueError("Vulnerable code required")
    
    def estimate_cost(self, **kwargs) -> ResourceEstimate:
        """Estimate fix recommendation cost."""
        code = kwargs.get('code', '')
        code_lines = len(code.split('\n'))
        estimated_tokens = (code_lines * 20) + 1000  # Code + prompt + fix
        
        return ResourceEstimate(
            tokens=estimated_tokens,
            time_ms=3500,
            memory_items=1,
            llm_calls=1,
            complexity=0.8,
            confidence=0.8
        )
    
    def rollback(self, context: ExecutionContext) -> None:
        """No side effects to rollback."""
        pass
    
    def execute(self, context: ExecutionContext, working_memory: WorkingMemory,
                semantic_memory: Optional[SemanticMemory] = None, **kwargs) -> PrimitiveResult:
        """
        Generate fix recommendations for a vulnerability.
        
        Args:
            vulnerability: Vulnerability details (CWE, name, description)
            code: Vulnerable code snippet
            file_path: Optional file path
            
        Returns:
            PrimitiveResult with fix recommendations
        """
        start_time = time.time()
        vulnerability = kwargs.get('vulnerability')
        code = kwargs.get('code')
        file_path = kwargs.get('file_path', 'unknown')
        
        logger.info(f"Generating fix for {vulnerability.get('name', 'unknown')}")
        
        # Search for remediation patterns in semantic memory
        remediation_context = ""
        if semantic_memory:
            from brainary.memory.semantic import KnowledgeType
            remediation_patterns = semantic_memory.search(
                query=f"fix {vulnerability.get('name', '')} remediation",
                knowledge_types=[KnowledgeType.PROCEDURAL],
                top_k=2
            )
            if remediation_patterns:
                remediation_context = "\n\nKnown remediation patterns:\n"
                for pattern in remediation_patterns:
                    remediation_context += f"- {pattern.description}\n"
        
        # Build fix recommendation prompt
        system_prompt = """You are a senior security engineer providing remediation guidance.
Generate specific, actionable fix recommendations for Java security vulnerabilities.

Your recommendations should:
1. Provide secure code alternatives
2. Explain why the fix addresses the vulnerability
3. Include best practices and OWASP guidelines
4. Be directly applicable to the code
5. Consider performance and maintainability"""

        vuln_desc = f"""CWE: {vulnerability.get('cwe_id', 'N/A')}
Vulnerability: {vulnerability.get('name', 'Unknown')}
Severity: {vulnerability.get('severity', 'Unknown')}
Description: {vulnerability.get('description', 'N/A')}"""

        user_prompt = f"""Generate fix recommendations for this vulnerability:

{vuln_desc}

Vulnerable code (from {file_path}):
```java
{code}
```
{remediation_context}

Provide remediation in JSON format:
{{
  "priority": "Immediate/High/Medium",
  "fix_summary": "Brief description of fix",
  "secure_code_example": "Fixed code snippet",
  "explanation": "Why this fix works",
  "additional_recommendations": ["Other security improvements"],
  "owasp_reference": "Relevant OWASP guidelines"
}}"""

        try:
            from brainary.llm.manager import get_llm_manager
            
            llm_manager = get_llm_manager()
            response = llm_manager.request(
                messages=[
                    {"role": "system", "content": system_prompt},
                    {"role": "user", "content": user_prompt}
                ],
                provider="openai",
                model="gpt-4o-mini",
                temperature=0.3,
                max_tokens=2000
            )
            
            # Parse recommendations
            import json
            recommendation_text = response.content
            json_match = re.search(r'\{.*\}', recommendation_text, re.DOTALL)
            
            if json_match:
                recommendations = json.loads(json_match.group())
            else:
                recommendations = {
                    "priority": "High",
                    "fix_summary": recommendation_text,
                    "secure_code_example": "See analysis",
                    "explanation": recommendation_text
                }
            
            # Store remediation in working memory
            working_memory.store(
                content={
                    "action": "recommend_fix",
                    "vulnerability": vulnerability.get('name', 'unknown'),
                    "priority": recommendations.get('priority'),
                    "has_code_example": bool(recommendations.get('secure_code_example'))
                },
                importance=0.85,
                tags=["remediation", "fix"]
            )
            
            # Also store in semantic memory as procedural knowledge
            if semantic_memory:
                from brainary.memory.semantic import ProceduralKnowledge
                import uuid
                
                fix_entry = ProceduralKnowledge(
                    entry_id=f"fix_{vulnerability.get('cwe_id', 'unknown')}_{uuid.uuid4().hex[:8]}",
                    key_concepts=["remediation", vulnerability.get('cwe_id', ''), vulnerability.get('name', '')],
                    description=recommendations.get('fix_summary', 'Security fix recommendation'),
                    procedure_type="remediation",
                    implementation=recommendations.get('secure_code_example', ''),
                    importance=0.85,
                    metadata={
                        "vulnerability": vulnerability.get('name'),
                        "cwe_id": vulnerability.get('cwe_id'),
                        "fix_pattern": recommendations.get('fix_summary'),
                        "code_example": recommendations.get('secure_code_example')
                    }
                )
                semantic_memory.add_knowledge(fix_entry)
            
            logger.info(f"Fix recommendations generated: {recommendations.get('priority')} priority")
            
            return create_result(
                content=recommendations,
                confidence=0.85,
                metadata={
                    "primitive": "recommend_fix",
                    "vulnerability": vulnerability.get('name', 'unknown'),
                    "cwe_id": vulnerability.get('cwe_id', 'N/A')
                },
                context=context,
                success=True,
                start_time=start_time,
                primitive_name="recommend_fix"
            )
            
        except Exception as e:
            logger.error(f"Fix recommendation failed: {e}")
            return create_result(
                content={"error": str(e)},
                confidence=0.0,
                metadata={"primitive": "recommend_fix", "error_type": type(e).__name__},
                context=context,
                success=False,
                start_time=start_time,
                primitive_name="recommend_fix"
            )
