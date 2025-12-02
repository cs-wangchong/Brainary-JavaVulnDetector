"""
Security Detector Agent

TemplateAgent-based intelligent security detector with custom process() method,
domain-specific primitives, semantic memory, and metacognitive rules.
"""

from typing import Any, Dict, List, Optional
from pathlib import Path
import logging
import time

from brainary.sdk import TemplateAgent
from brainary.core.context import ExecutionContext, ExecutionMode
from brainary.core.kernel import CognitiveKernel
from brainary.memory.working import WorkingMemory
from brainary.memory.semantic import SemanticMemory
from brainary.primitive.base import PrimitiveResult, CostMetrics, ConfidenceMetrics

from .security_primitives import (
    ScanCodePrimitive,
    AnalyzeVulnerabilityPrimitive,
    ValidateFindingPrimitive,
    RecommendFixPrimitive
)
from .security_knowledge import initialize_security_knowledge, get_vulnerability_context
from .security_metacognition import create_security_metacognitive_rules

logger = logging.getLogger(__name__)


class SecurityDetectorAgent(TemplateAgent):
    """
    Intelligent Java Security Detector Agent.
    
    Extends TemplateAgent with security-specific:
    - Custom primitives (scan, analyze, validate, recommend_fix)
    - Semantic memory (OWASP, CWE, remediation patterns)
    - Metacognitive rules (quality, false positive filtering)
    - Comprehensive process() method for detection pipeline
    
    Usage:
        agent = SecurityDetectorAgent(name="java_security_detector")
        result = agent.run(target_path)
    """
    
    def __init__(self, name: str = "SecurityDetector", **kwargs):
        """
        Initialize security detector agent.
        
        Args:
            name: Agent name
            **kwargs: Additional configuration
        """
        # Initialize parent with security domain
        super().__init__(
            name=name,
            description="Intelligent Java vulnerability detector with LLM-powered analysis",
            **kwargs
        )
        
        # Register custom security primitives
        self._register_security_primitives()
        
        # Initialize security knowledge in semantic memory
        initialize_security_knowledge(self.semantic_memory)
        logger.info("Security knowledge initialized in semantic memory")
        
        # Set up metacognitive rules for security
        self.metacognitive_rules = create_security_metacognitive_rules()
        logger.info(f"Created {len(self.metacognitive_rules)} metacognitive rules")
        
        # Detection statistics
        self.stats = {
            "total_scans": 0,
            "total_findings": 0,
            "validated_findings": 0,
            "false_positives_filtered": 0,
            "remediations_generated": 0
        }
    
    def _register_security_primitives(self) -> None:
        """Register domain-specific security primitives globally."""
        from brainary.primitive import register_implementation, get_primitive_catalog, PrimitiveLevel, PrimitiveDef
        
        # Get catalog to register primitive definitions
        catalog = get_primitive_catalog()
        
        # Register primitive definitions in catalog (if not already registered)
        primitives_to_register = [
            PrimitiveDef(
                name="scan_code",
                description="Scan code for potential vulnerabilities",
                level=PrimitiveLevel.DOMAIN,
                tags={"security", "scanning"}
            ),
            PrimitiveDef(
                name="analyze_vulnerability",
                description="Deep LLM analysis of vulnerabilities",
                level=PrimitiveLevel.DOMAIN,
                tags={"security", "analysis"}
            ),
            PrimitiveDef(
                name="validate_finding",
                description="Validate findings to filter false positives",
                level=PrimitiveLevel.DOMAIN,
                tags={"security", "validation"}
            ),
            PrimitiveDef(
                name="recommend_fix",
                description="Generate remediation recommendations",
                level=PrimitiveLevel.DOMAIN,
                tags={"security", "remediation"}
            )
        ]
        
        for prim_def in primitives_to_register:
            try:
                catalog.register(prim_def)
            except ValueError:
                # Already registered, skip
                pass
        
        # Create primitive instances
        scan_primitive = ScanCodePrimitive()
        analyze_primitive = AnalyzeVulnerabilityPrimitive()
        validate_primitive = ValidateFindingPrimitive()
        fix_primitive = RecommendFixPrimitive()
        
        # Register implementations with the router
        register_implementation("scan_code", scan_primitive)
        register_implementation("analyze_vulnerability", analyze_primitive)
        register_implementation("validate_finding", validate_primitive)
        register_implementation("recommend_fix", fix_primitive)
        
        logger.info("Registered 4 security primitives: scan_code, analyze_vulnerability, validate_finding, recommend_fix")
    
    def process(self, input_data: Any, context: Optional[ExecutionContext] = None, **kwargs) -> PrimitiveResult:
        """
        Execute security detection pipeline.
        
        Pipeline stages:
        1. Scan: Find potential vulnerabilities using pattern matching
        2. Analyze: Deep LLM-powered analysis of findings
        3. Validate: Filter false positives
        4. Remediate: Generate fix recommendations
        5. Learn: Store results in memory for continuous improvement
        
        Args:
            input_data: Target file or directory path to scan
            context: Execution context
            **kwargs: Additional options (deep_analysis, validate, remediate, max_findings)
        
        Returns:
            PrimitiveResult with complete detection report
        """
        target = str(input_data)
        start_time = time.time()
        
        # Create execution context if not provided
        if context is None:
            context = ExecutionContext(program_name="security_detection")
        
        # Extract options
        deep_analysis = kwargs.get('deep_analysis', True)
        validate = kwargs.get('validate', True)
        remediate = kwargs.get('remediate', True)
        max_findings = kwargs.get('max_findings', 50)
        
        logger.info(f"Starting security detection pipeline for: {target}")
        logger.info(f"Options: deep_analysis={deep_analysis}, validate={validate}, remediate={remediate}")
        
        try:
            # Stage 1: Scan
            scan_result = self._scan_stage(target, context)
            if not scan_result.success:
                return self._create_error_result("Scan failed", scan_result.content)
            
            findings = scan_result.content.get('findings', [])
            self.stats['total_scans'] += 1
            self.stats['total_findings'] += len(findings)
            
            logger.info(f"Scan complete: {len(findings)} potential vulnerabilities found")
            
            if not findings:
                processing_time = int((time.time() - start_time) * 1000)
                return PrimitiveResult(
                    content={
                        "status": "clean",
                        "findings": [],
                        "message": "No vulnerabilities detected"
                    },
                    confidence=ConfidenceMetrics(overall=0.9, reasoning=0.9, completeness=0.9, consistency=0.9, evidence_strength=0.9),
                    execution_mode=context.execution_mode,
                    cost=CostMetrics(tokens=0, latency_ms=processing_time, memory_slots=0, provider_cost_usd=0.0),
                    metadata={"processing_time_ms": processing_time, "files_scanned": 1},
                    success=True
                )
            
            # Limit findings to process
            findings = findings[:max_findings]
            
            # Stage 2: Deep Analysis (optional)
            if deep_analysis:
                findings = self._analyze_stage(findings, context)
                logger.info(f"Analysis complete: {len(findings)} findings analyzed")
            
            # Stage 3: Validation (optional)
            if validate:
                findings = self._validate_stage(findings, context)
                logger.info(f"Validation complete: {len(findings)} findings validated")
            
            # Stage 4: Remediation (optional)
            if remediate:
                findings = self._remediate_stage(findings, context)
                logger.info(f"Remediation complete: {len(findings)} with fixes")
            
            # Stage 5: Metacognitive Review
            self._metacognitive_review(findings, context, start_time)
            
            # Stage 6: Learn - Store episodic memory
            self._learn_from_detection(target, findings, context)
            
            processing_time = int((time.time() - start_time) * 1000)
            
            # Generate summary
            summary = self._generate_summary(target, findings, processing_time)
            
            logger.info(f"Detection pipeline complete: {len(findings)} final findings in {processing_time}ms")
            
            return PrimitiveResult(
                content={
                    "target": target,
                    "findings": findings,
                    "findings_count": len(findings),
                    "summary": summary,
                    "statistics": self.stats.copy(),
                    "processing_time_ms": processing_time
                },
                confidence=ConfidenceMetrics(overall=0.9, reasoning=0.9, completeness=0.9, consistency=0.9, evidence_strength=0.9),
                execution_mode=context.execution_mode,
                cost=CostMetrics(tokens=0, latency_ms=processing_time, memory_slots=len(findings), provider_cost_usd=0.0),
                metadata={
                    "pipeline_stages": ["scan", "analyze", "validate", "remediate"],
                    "processing_time_ms": processing_time
                },
                success=True
            )
            
        except Exception as e:
            logger.error(f"Detection pipeline failed: {e}", exc_info=True)
            return self._create_error_result("Pipeline error", str(e))
    
    def _scan_stage(self, target: str, context: ExecutionContext) -> PrimitiveResult:
        """Stage 1: Scan code for vulnerabilities."""
        logger.info(f"[Stage 1] Scanning: {target}")
        
        return self.kernel.execute(
            "scan_code",
            context=context,
            target=target,
            use_patterns=True
        )
    
    def _analyze_stage(self, findings: List[Dict], context: ExecutionContext) -> List[Dict]:
        """Stage 2: Deep analysis of findings."""
        logger.info(f"[Stage 2] Analyzing {len(findings)} findings")
        
        analyzed_findings = []
        
        for i, finding in enumerate(findings, 1):
            code = finding.get('match', '') or finding.get('snippet', '')
            if not code:
                analyzed_findings.append(finding)
                continue
            
            # Get vulnerability context from semantic memory
            vuln_type = finding.get('name', '')
            knowledge = get_vulnerability_context(self.semantic_memory, vuln_type, top_k=3)
            
            # Analyze with LLM
            analysis_result = self.kernel.execute(
                "analyze_vulnerability",
                context=context,
                code=code,
                vulnerability_type=vuln_type,
                file_path=finding.get('file', 'unknown'),
                semantic_memory=self.semantic_memory
            )
            
            if analysis_result.success:
                # Merge analysis into finding
                analysis = analysis_result.content
                finding['analysis'] = analysis
                finding['vulnerabilities_detailed'] = analysis.get('vulnerabilities', [])
                finding['overall_risk'] = analysis.get('overall_risk', 'unknown')
                
                logger.debug(f"Analyzed finding {i}: {len(analysis.get('vulnerabilities', []))} detailed vulnerabilities")
            
            analyzed_findings.append(finding)
        
        return analyzed_findings
    
    def _validate_stage(self, findings: List[Dict], context: ExecutionContext) -> List[Dict]:
        """Stage 3: Validate findings to filter false positives."""
        logger.info(f"[Stage 3] Validating {len(findings)} findings")
        
        validated_findings = []
        false_positives = 0
        
        for i, finding in enumerate(findings, 1):
            # Validate finding
            validation_result = self.kernel.execute(
                "validate_finding",
                context=context,
                finding=finding,
                code_context=finding.get('context', '')
            )
            
            if validation_result.success:
                validation = validation_result.content
                finding['validation'] = validation
                
                # Keep finding if validated or uncertain
                is_valid = validation.get('is_valid', True)
                recommendation = validation.get('recommendation', 'Keep')
                
                if is_valid or recommendation != 'Dismiss':
                    finding['validated'] = True
                    validated_findings.append(finding)
                    self.stats['validated_findings'] += 1
                else:
                    logger.debug(f"Filtered false positive {i}: {finding.get('name')} - {validation.get('reasoning', '')}")
                    false_positives += 1
                    self.stats['false_positives_filtered'] += 1
            else:
                # Keep finding if validation fails (fail-safe)
                finding['validated'] = False
                validated_findings.append(finding)
        
        logger.info(f"Validation filtered {false_positives} false positives, {len(validated_findings)} remain")
        
        return validated_findings
    
    def _remediate_stage(self, findings: List[Dict], context: ExecutionContext) -> List[Dict]:
        """Stage 4: Generate remediation recommendations."""
        logger.info(f"[Stage 4] Generating remediation for {len(findings)} findings")
        
        remediated_findings = []
        
        for i, finding in enumerate(findings, 1):
            # Extract vulnerability details
            vulnerabilities = finding.get('vulnerabilities_detailed', [])
            code = finding.get('match', '') or finding.get('snippet', '')
            
            if not vulnerabilities or not code:
                remediated_findings.append(finding)
                continue
            
            # Generate fix for first/primary vulnerability
            primary_vuln = vulnerabilities[0] if vulnerabilities else {
                'name': finding.get('name', 'Unknown'),
                'cwe_id': finding.get('cwe_id', 'N/A'),
                'severity': finding.get('severity', 'Unknown'),
                'description': finding.get('description', '')
            }
            
            fix_result = self.kernel.execute(
                "recommend_fix",
                context=context,
                vulnerability=primary_vuln,
                code=code,
                file_path=finding.get('file', 'unknown'),
                semantic_memory=self.semantic_memory
            )
            
            if fix_result.success:
                finding['remediation'] = fix_result.content
                self.stats['remediations_generated'] += 1
                logger.debug(f"Generated fix {i}: {fix_result.content.get('priority', 'N/A')} priority")
            
            remediated_findings.append(finding)
        
        return remediated_findings
    
    def _metacognitive_review(self, findings: List[Dict], context: ExecutionContext, start_time: float) -> None:
        """Stage 5: Metacognitive review and quality assessment."""
        logger.info(f"[Stage 5] Metacognitive review")
        
        processing_time = int((time.time() - start_time) * 1000)
        
        # Prepare metadata for rules
        metadata = {
            'findings': findings,
            'findings_count': len(findings),
            'processing_time_ms': processing_time,
            'files_scanned': 1  # TODO: Track actual file count
        }
        
        # Evaluate rules
        for rule in self.metacognitive_rules:
            result = rule.evaluate(context, metadata)
            
            if not result.passed:
                logger.warning(f"Rule '{rule.name}' failed: {result.feedback}")
                if result.recommendations:
                    for rec in result.recommendations:
                        logger.warning(f"  → {rec}")
            else:
                logger.debug(f"Rule '{rule.name}' passed: {result.feedback}")
    
    def _learn_from_detection(self, target: str, findings: List[Dict], context: ExecutionContext) -> None:
        """Stage 6: Store detection results in episodic memory for learning."""
        logger.info(f"[Stage 6] Storing detection results in memory")
        
        # Store detection episode in semantic memory as conceptual knowledge
        from brainary.memory.semantic import ConceptualKnowledge
        import uuid
        
        detection_entry = ConceptualKnowledge(
            entry_id=f"detection_{uuid.uuid4().hex[:8]}",
            key_concepts=["detection", "episode", Path(target).name],
            description=f"Security detection on {target} found {len(findings)} vulnerabilities",
            relationships=[f.get('cwe_id', 'N/A') for f in findings if f.get('cwe_id')],
            importance=0.7,
            metadata={
                "target": target,
                "timestamp": time.time(),
                "findings_count": len(findings),
                "critical_findings": len([f for f in findings if f.get('severity', '').lower() == 'critical']),
                "high_findings": len([f for f in findings if f.get('severity', '').lower() == 'high']),
                "cwe_ids": list(set(f.get('cwe_id', 'N/A') for f in findings)),
                "context_id": context.context_id
            }
        )
        self.semantic_memory.add_knowledge(detection_entry)
        
        # Store significant findings in working memory
        for finding in findings[:3]:  # Store top 3 in working memory
            self.working_memory.store(
                content={
                    "name": finding.get('name'),
                    "severity": finding.get('severity'),
                    "file": finding.get('file'),
                    "validated": finding.get('validated', False)
                },
                importance=0.9 if finding.get('severity', '').lower() == 'critical' else 0.7,
                tags=["finding", "detection"]
            )
    
    def _generate_summary(self, target: str, findings: List[Dict], processing_time: int) -> str:
        """Generate human-readable detection summary."""
        # Count by severity
        critical = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
        high = len([f for f in findings if f.get('severity', '').lower() == 'high'])
        medium = len([f for f in findings if f.get('severity', '').lower() == 'medium'])
        low = len([f for f in findings if f.get('severity', '').lower() == 'low'])
        
        # Count validated
        validated = len([f for f in findings if f.get('validated', False)])
        
        # Count with remediation
        with_fixes = len([f for f in findings if f.get('remediation')])
        
        summary_lines = [
            f"Security Detection Report for: {target}",
            f"",
            f"Total Findings: {len(findings)}",
            f"  • Critical: {critical}",
            f"  • High: {high}",
            f"  • Medium: {medium}",
            f"  • Low: {low}",
            f"",
            f"Validated: {validated}/{len(findings)}",
            f"With Remediation: {with_fixes}/{len(findings)}",
            f"",
            f"Processing Time: {processing_time}ms",
            f"",
            f"Top Vulnerabilities:",
        ]
        
        # Add top 5 findings
        for i, finding in enumerate(findings[:5], 1):
            name = finding.get('name', 'Unknown')
            severity = finding.get('severity', 'Unknown')
            file_path = finding.get('file', 'unknown')
            line = finding.get('line', '?')
            summary_lines.append(f"  {i}. [{severity}] {name} at {file_path}:{line}")
        
        return "\n".join(summary_lines)
    
    def _create_error_result(self, error_type: str, error_message: str) -> PrimitiveResult:
        """Create error result."""
        return PrimitiveResult(
            content={
                "error_type": error_type,
                "error_message": error_message
            },
            confidence=ConfidenceMetrics(overall=0.0, reasoning=0.0, completeness=0.0, consistency=0.0, evidence_strength=0.0),
            execution_mode=ExecutionMode.ADAPTIVE,
            cost=CostMetrics(tokens=0, latency_ms=0, memory_slots=0, provider_cost_usd=0.0),
            metadata={"error": True},
            success=False
        )
    
    def get_detection_stats(self) -> Dict[str, Any]:
        """Get detection statistics."""
        return {
            **self.stats,
            "agent_stats": self.get_stats()
        }
    
    def reset_stats(self) -> None:
        """Reset detection statistics."""
        self.stats = {
            "total_scans": 0,
            "total_findings": 0,
            "validated_findings": 0,
            "false_positives_filtered": 0,
            "remediations_generated": 0
        }
