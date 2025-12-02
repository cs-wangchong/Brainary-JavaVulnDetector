"""
Java Security Detection Agents

Multi-agent system for intelligent vulnerability detection.
"""

from typing import Any, Dict, List, Optional
from dataclasses import dataclass
from pathlib import Path
import logging

from brainary.core.context import ExecutionContext
from brainary.core.kernel import CognitiveKernel
from brainary.sdk.agents import Agent, AgentConfig, AgentRole
from brainary.memory.working import WorkingMemory
from .knowledge import VulnerabilityKnowledgeBase
from .tools import SecurityScanner, ToolResult, ToolStatus
from .primitives import (
    ThinkSecurityPrimitive,
    DetectVulnerabilityPrimitive,
    ValidateFindingPrimitive,
    RecommendFixPrimitive
)

logger = logging.getLogger(__name__)


@dataclass
class SecurityFinding:
    """Represents a security finding"""
    cwe_id: str
    name: str
    severity: str
    file_path: str
    line_number: int
    code_snippet: str
    description: str
    confidence: str
    remediation: Optional[str] = None
    validated: bool = False


class ScannerAgent:
    """
    Scanner Agent: Initial code scanning and triage.
    
    Responsibilities:
    - Scan code for potential vulnerabilities
    - Run static analysis tools
    - Perform initial triage
    - Flag suspicious code patterns
    """
    
    def __init__(self, kernel: Optional[CognitiveKernel] = None, name: str = "SecurityScanner"):
        self.kernel = kernel or CognitiveKernel()
        self.name = name
        self.scanner = SecurityScanner(use_codeql=False)
        self.kb = VulnerabilityKnowledgeBase()
        self.memory = WorkingMemory(capacity=7)
    
    def execute(self, target: str, scan_options: Optional[Dict] = None) -> Dict[str, Any]:
        """
        Scan target for vulnerabilities.
        
        Args:
            target: File or directory to scan
            scan_options: Optional scanning configuration
        
        Returns:
            Dictionary with scan results
        """
        scan_options = scan_options or {}
        
        # Scan using security scanner (returns dict of tool results)
        scan_results = self.scanner.scan(target, use_codeql=False, use_patterns=True)
        
        # Combine findings from all tools
        all_findings = []
        for tool_name, tool_result in scan_results.items():
            if tool_result.status != ToolStatus.SUCCESS:
                logger.warning(f"Tool {tool_name} failed: {tool_result.message}")
                continue
            all_findings.extend(tool_result.findings)
        
        if not scan_results:
            return {"success": False, "error": "No scan results returned"}
        
        # Log scan summary
        logger.info(f"Scan complete: {len(all_findings)} potential vulnerabilities found")
        
        # Organize findings by severity
        organized_findings = self._organize_findings(all_findings)
        
        return {
            "success": True,
            "findings_count": len(all_findings),
            "findings": all_findings,
            "organized": organized_findings,
            "metadata": {"tools": list(scan_results.keys()), "findings_per_tool": {k: len(v.findings) for k, v in scan_results.items()}}
        }
    
    def _organize_findings(self, findings: List[Dict]) -> Dict[str, List[Dict]]:
        """Organize findings by severity/category"""
        organized = {
            "critical": [],
            "high": [],
            "medium": [],
            "low": []
        }
        
        for finding in findings:
            # Try to determine severity from description or pattern
            description = finding.get("description", "").lower()
            if "sql injection" in description or "command injection" in description:
                organized["critical"].append(finding)
            elif "xss" in description or "path traversal" in description:
                organized["high"].append(finding)
            else:
                organized["medium"].append(finding)
        
        return organized


class AnalyzerAgent:
    """
    Analyzer Agent: Deep analysis and vulnerability assessment.
    
    Responsibilities:
    - Perform deep security analysis
    - Understand attack vectors
    - Assess exploitability
    - Provide technical details
    
    Uses Brainary kernel for intelligent primitive orchestration,
    memory management, and learning from analysis patterns.
    """
    
    def __init__(self, kernel: Optional[CognitiveKernel] = None, name: str = "SecurityAnalyzer"):
        self.kernel = kernel or CognitiveKernel()
        self.name = name
        
        # Create agent config for high-level operations
        config = AgentConfig(
            name=name,
            role=AgentRole.RESEARCHER,
            domain="security",
            description="Analyzes vulnerabilities and assesses risk",
            quality_threshold=0.85,
            default_mode="deep"
        )
        self.agent = Agent.from_config(config)
        
        # Knowledge base
        self.kb = VulnerabilityKnowledgeBase()
        
        # Working memory for analysis context
        self.memory = WorkingMemory(capacity=10)
        
        # Track decisions for analysis reflection
        self.decisions: List[Dict[str, Any]] = []
        
        # Store context for conditional evaluation
        self.context = None
    
    def execute(self, context: ExecutionContext, findings: List[Dict],
                focus_areas: Optional[List[str]] = None) -> Dict[str, Any]:
        """
        Analyze findings in depth with intelligent control flow.
        
        Args:
            context: Execution context
            findings: Findings from scanner
            focus_areas: Optional areas to focus on
        
        Returns:
            Dictionary with analysis results
        """
        logger.info(f"AnalyzerAgent analyzing {len(findings)} findings")
        
        # Store context for conditional evaluation
        self.context = context
        self.decisions.clear()
        
        analyzed_findings = []
        skipped_findings = []
        failed_analyses = 0
        
        # Analyze each finding with intelligent prioritization
        max_findings = min(len(findings), 50)
        for i, finding in enumerate(findings[:max_findings], 1):
            logger.debug(f"Analyzing finding {i}/{max_findings}")
            
            # Use conditional primitive to decide if deep analysis is needed
            if self._should_analyze_deeply(finding):
                logger.debug(f"Deep analysis for finding {i}")
                analysis = self._analyze_finding(context, finding, focus_areas)
                if analysis:
                    analyzed_findings.append(analysis)
                else:
                    # Keep finding even if analysis fails
                    failed_analyses += 1
                    logger.warning(f"Analysis failed for finding at {finding.get('file')}:{finding.get('line')}")
                    analyzed_findings.append(finding)
            else:
                # Skip low-priority findings with conditional logic
                logger.debug(f"Skipping low-priority finding {i}")
                finding['skipped'] = True
                finding['skip_reason'] = 'Low priority based on intelligent triage'
                skipped_findings.append(finding)
        
        logger.info(f"Completed analysis: {len(analyzed_findings)} analyzed, {len(skipped_findings)} skipped, {failed_analyses} failed")
        
        # Generate summary with control flow insights
        summary = self._generate_summary(analyzed_findings)
        
        # Add control flow decision summary
        decision_summary = self._get_decision_summary()
        summary += f"\n\nControl Flow Decisions: {decision_summary['total_decisions']} made, {decision_summary['conditions_met']} conditions met"
        
        return {
            "success": True,
            "analyzed_count": len(analyzed_findings),
            "skipped_count": len(skipped_findings),
            "findings": analyzed_findings,
            "skipped_findings": skipped_findings,
            "summary": summary,
            "control_flow_stats": decision_summary
        }
    
    def _analyze_finding(self, context: ExecutionContext, finding: Dict,
                        focus_areas: Optional[List[str]]) -> Optional[Dict]:
        """
        Analyze a single finding using kernel orchestration.
        
        Routes through kernel.execute() to leverage:
        - Intelligent primitive routing
        - Memory management and context
        - Learning from analysis patterns
        - Resource management
        """
        # Extract code if available
        code = finding.get("match", "") or finding.get("snippet", "")
        if not code:
            return None
        
        # Get context
        code_context = finding.get("context", code)
        
        # Use kernel to execute think_security primitive for intelligent analysis
        # The kernel will:
        # 1. Route to optimal ThinkSecurityPrimitive implementation
        # 2. Manage memory and context
        # 3. Learn from execution patterns
        # 4. Handle resource allocation
        result = self.kernel.execute(
            "think_security",
            context=context,
            working_memory=self.memory,
            code_context=code_context,
            focus=focus_areas[0] if focus_areas else None
        )
        
        logger.debug(f"Kernel execute result: success={result.success}, content_len={len(str(result.content)) if result.content else 0}")
        
        if result.success:
            # Enhance finding with analysis
            finding["analysis"] = result.content  # Fixed: Use content not output
            finding["vulnerabilities"] = result.metadata.get("vulnerabilities", [])
            finding["severity_assessment"] = result.metadata.get("severity_counts", {})
            logger.debug(f"Finding enhanced with {len(finding.get('vulnerabilities', []))} vulnerabilities")
            return finding
        else:
            logger.warning(f"Kernel execute failed: {result.error if hasattr(result, 'error') else 'Unknown error'}")
        
        return None
    
    def _should_analyze_deeply(self, finding: Dict[str, Any]) -> bool:
        """
        Decide if finding requires deep analysis using Brainary's conditional primitive.
        
        Args:
            finding: Finding to evaluate
        
        Returns:
            True if deep analysis recommended
        """
        severity = finding.get("severity", "medium").lower()
        
        # Check severity first
        result = self.kernel.execute(
            "conditional",
            self.context,
            self.memory,
            condition="the severity is critical or high",
            if_true="true",
            if_false="false",
            severity=severity,
            description=finding.get("description", "")
        )
        
        if result.success and result.content:
            decision = result.content.get('condition_result', False)
            if decision:
                self._record_decision("severity_check", True, result.confidence.overall)
                logger.debug(f"Deep analysis: High severity ({severity})")
                return True
        
        # Check if it's a well-known dangerous pattern
        result = self.kernel.execute(
            "conditional",
            self.context,
            self.memory,
            condition="the vulnerability is a well-known dangerous pattern like SQL injection, XXE, or deserialization",
            if_true="true",
            if_false="false",
            description=finding.get("description", ""),
            cwe_id=finding.get("cwe_id", "")
        )
        
        if result.success and result.content:
            decision = result.content.get('condition_result', False)
            if decision:
                self._record_decision("dangerous_pattern_check", True, result.confidence.overall)
                logger.debug(f"Deep analysis: Dangerous pattern")
                return True
        
        # Check if code context suggests real vulnerability
        code = finding.get("code_snippet", "")
        if code:
            result = self.kernel.execute(
                "conditional",
                self.context,
                self.memory,
                condition="the code snippet contains user input handling without proper sanitization or validation",
                if_true="true",
                if_false="false",
                code=code,
                file_path=finding.get("file", "")
            )
            
            if result.success and result.content:
                decision = result.content.get('condition_result', False)
                if decision:
                    self._record_decision("unsanitized_input_check", True, result.confidence.overall)
                    logger.debug(f"Deep analysis: Unsanitized input detected")
                    return True
        
        self._record_decision("skip_analysis", False, 1.0)
        return False
    
    def _record_decision(self, condition_type: str, result: bool, confidence: float) -> None:
        """Record a decision for later reflection"""
        self.decisions.append({
            "type": condition_type,
            "result": result,
            "confidence": confidence
        })
    
    def _get_decision_summary(self) -> Dict[str, Any]:
        """Get summary of all decisions made during analysis"""
        total = len(self.decisions)
        conditions_met = sum(1 for d in self.decisions if d["result"])
        avg_confidence = sum(d["confidence"] for d in self.decisions) / total if total > 0 else 0.0
        
        return {
            "total_decisions": total,
            "conditions_met": conditions_met,
            "average_confidence": avg_confidence
        }
    
    def _generate_summary(self, findings: List[Dict]) -> str:
        """Generate analysis summary"""
        if not findings:
            return "No findings to analyze"
        
        summary = f"Analyzed {len(findings)} findings:\n\n"
        
        # Count vulnerability types
        vuln_types = {}
        for finding in findings:
            for vuln in finding.get("vulnerabilities", []):
                cwe_id = vuln.get("cwe_id")
                if cwe_id:
                    vuln_types[cwe_id] = vuln_types.get(cwe_id, 0) + 1
        
        if vuln_types:
            summary += "Vulnerability Distribution:\n"
            for cwe_id, count in sorted(vuln_types.items(), key=lambda x: x[1], reverse=True):
                pattern = self.kb.get_pattern(cwe_id)
                name = pattern.name if pattern else "Unknown"
                summary += f"  • {cwe_id} ({name}): {count}\n"
        
        return summary


class ValidatorAgent:
    """
    Validator Agent: Verification and false positive elimination.
    
    Responsibilities:
    - Validate findings
    - Eliminate false positives
    - Assess confidence levels
    - Confirm exploitability
    
    Uses Brainary kernel for intelligent validation routing and learning.
    """
    
    def __init__(self, kernel: Optional[CognitiveKernel] = None, name: str = "SecurityValidator"):
        self.kernel = kernel or CognitiveKernel()
        self.name = name
        
        # Create agent config
        config = AgentConfig(
            name=name,
            role=AgentRole.REVIEWER,
            domain="security",
            description="Validates findings and eliminates false positives",
            quality_threshold=0.90,
            default_mode="deep"
        )
        self.agent = Agent.from_config(config)
        
        # Working memory for validation context
        self.memory = WorkingMemory(capacity=10)
        
        # Track decisions for validation reflection
        self.decisions: List[Dict[str, Any]] = []
        
        # Store context for conditional evaluation
        self.context = None
    
    def execute(self, context: ExecutionContext, findings: List[Dict]) -> Dict[str, Any]:
        """
        Validate findings with intelligent control flow.
        
        Args:
            context: Execution context
            findings: Findings to validate
        
        Returns:
            Dictionary with validation results
        """
        logger.info(f"ValidatorAgent validating {len(findings)} findings")
        
        # Store context for conditional evaluation
        self.context = context
        self.decisions.clear()
        
        validated_findings = []
        false_positives = []
        skipped_validation = []
        
        for i, finding in enumerate(findings, 1):
            logger.debug(f"Validating finding {i}/{len(findings)}")
            
            # Use conditional primitive to decide if validation can be skipped
            if self._should_skip_validation(finding, finding.get('analysis')):
                logger.debug(f"Skipping validation for finding {i} - clear false positive")
                finding["validated"] = False
                finding["false_positive_reason"] = "Pattern-based false positive detection"
                false_positives.append(finding)
                skipped_validation.append(finding)
                continue
            
            # Perform validation with control flow awareness
            validation = self._validate_finding(context, finding)
            
            if validation is None:
                # Validation failed - use conditional to decide what to do
                decision = self._conditional(
                    "the finding should be assumed valid when validation fails (security-first approach)",
                    finding=finding,
                    severity=finding.get('severity', 'medium')
                )
                
                if decision:
                    logger.warning(f"Validation failed for finding at {finding.get('file')}:{finding.get('line')}, assuming valid (security-first)")
                    finding["validated"] = True
                    finding["confidence"] = "medium"
                    finding["validation_notes"] = "Validation failed - assumed valid for security"
                    validated_findings.append(finding)
                else:
                    logger.warning(f"Validation failed and low confidence - marking as false positive")
                    finding["validated"] = False
                    finding["false_positive_reason"] = "Validation failed with low confidence"
                    false_positives.append(finding)
            elif validation.get("valid"):
                # Assess confidence using reflection
                confidence = self._assess_confidence(finding, validation)
                finding["validated"] = True
                finding["confidence"] = validation.get("confidence", "medium")
                finding["confidence_score"] = confidence
                finding["validation_notes"] = validation.get("output", "")
                validated_findings.append(finding)
            else:
                finding["validated"] = False
                finding["false_positive_reason"] = validation.get("output", "")
                false_positives.append(finding)
        
        logger.info(
            f"Validation complete: {len(validated_findings)} confirmed, "
            f"{len(false_positives)} false positives, "
            f"{len(skipped_validation)} skipped"
        )
        
        # Get control flow insights
        decision_summary = self._get_decision_summary()
        
        # Use monitor primitive to get optimization insights
        optimization = self._get_optimization_insights()
        
        return {
            "success": True,
            "validated_count": len(validated_findings),
            "false_positive_count": len(false_positives),
            "skipped_validation_count": len(skipped_validation),
            "validated_findings": validated_findings,
            "false_positives": false_positives,
            "control_flow_stats": decision_summary,
            "optimization_insights": optimization
        }
    
    def _validate_finding(self, context: ExecutionContext, 
                         finding: Dict) -> Optional[Dict]:
        """
        Validate a single finding using kernel orchestration.
        
        Routes through kernel to enable:
        - Intelligent validation logic
        - Learning from validation patterns
        - Context-aware false positive detection
        """
        # Extract code context
        code_context = finding.get("context", "") or finding.get("match", "")
        if not code_context:
            return None
        
        # Need CWE ID for validation
        cwe_id = finding.get("cwe_id")
        if not cwe_id:
            # Try to extract from vulnerabilities
            vulns = finding.get("vulnerabilities", [])
            if vulns:
                cwe_id = vulns[0].get("cwe_id")
        
        if not cwe_id:
            return None
        
        # Prepare finding for validation
        validation_finding = {
            "cwe_id": cwe_id,
            "message": finding.get("description", ""),
            "file": finding.get("file", ""),
            "line": finding.get("line", 0)
        }
        
        # Execute validation through kernel for intelligent routing
        # Kernel will manage memory, learn patterns, optimize validation
        result = self.kernel.execute(
            "validate_finding",
            context=context,
            working_memory=self.memory,
            finding=validation_finding,
            code_context=code_context
        )
        
        if result.success:
            return {
                "valid": result.metadata.get("valid", False),
                "confidence": result.metadata.get("confidence", "medium"),
                "output": result.output
            }
        
        return None
    
    def _should_skip_validation(self, finding: Dict[str, Any], analysis: Optional[Dict] = None) -> bool:
        """
        Decide if validation can be skipped using Brainary's conditional primitive.
        
        Args:
            finding: Finding to evaluate
            analysis: Optional analysis result
        
        Returns:
            True if validation can be skipped
        """
        # Never skip validation for critical findings
        if finding.get("severity", "").lower() == "critical":
            return False
        
        # Skip validation if analysis shows clear false positive indicators
        if analysis:
            result = self.kernel.execute(
                "conditional",
                self.context,
                self.memory,
                condition="the analysis clearly shows this is a false positive with no exploitable path",
                if_true="true",
                if_false="false",
                analysis_result=analysis.get("analysis", ""),
                confidence=analysis.get("confidence", 0.0)
            )
            
            if result.success and result.content:
                decision = result.content.get('condition_result', False)
                if decision:
                    self._record_decision("skip_validation", True, result.confidence.overall)
                    logger.debug("Skipping validation: Clear false positive")
                    return True
        
        return False
    
    def _conditional(self, condition: str, **context_data) -> bool:
        """
        Evaluate a condition using Brainary's conditional primitive.
        
        Args:
            condition: Condition to evaluate
            **context_data: Context for condition evaluation
        
        Returns:
            Boolean result of condition evaluation
        """
        try:
            result = self.kernel.execute(
                "conditional",
                self.context,
                self.memory,
                condition=condition,
                if_true="true",
                if_false="false",
                **context_data
            )
            
            if result.success and result.content:
                decision = result.content.get('condition_result', False)
                self._record_decision("conditional", decision, result.confidence.overall)
                return bool(decision)
            
            return False
        except Exception as e:
            logger.error(f"Conditional evaluation failed: {e}")
            return True  # Default to conservative behavior
    
    def _assess_confidence(self, finding: Dict[str, Any], analysis: Optional[Dict] = None) -> float:
        """
        Assess confidence level in finding using Brainary's reflect primitive.
        
        Args:
            finding: Finding to assess
            analysis: Optional analysis result
        
        Returns:
            Confidence score (0.0 - 1.0)
        """
        try:
            # Use reflect primitive to assess confidence based on experience
            experience = {
                "finding": finding,
                "analysis": analysis,
                "decisions": self.decisions[-5:] if self.decisions else []
            }
            
            result = self.kernel.execute(
                "reflect",
                self.context,
                self.memory,
                experience=experience,
                focus="confidence_assessment"
            )
            
            if result.success and result.content:
                # Extract confidence from reflection
                insights = result.content.get("insights", [])
                if insights:
                    # Try to parse confidence from insights
                    for insight in insights:
                        if "confidence" in str(insight).lower():
                            try:
                                words = str(insight).split()
                                for word in words:
                                    if word.replace(".", "").isdigit():
                                        score = float(word)
                                        if 0 <= score <= 1:
                                            return score
                                        elif score > 1:
                                            return score / 100.0
                            except ValueError:
                                continue
                
                # Default: return transferability score if available
                return result.content.get("transferability_score", 0.7)
            
            return 0.7  # Default confidence
        except Exception as e:
            logger.error(f"Confidence assessment failed: {e}")
            return 0.7
    
    def _get_optimization_insights(self) -> Dict[str, Any]:
        """
        Get optimization insights using Brainary's monitor primitive.
        
        Returns:
            Dictionary with optimization insights
        """
        try:
            # Use monitor primitive to analyze detection strategy
            metrics = ["false_positive_rate", "validation_success_rate", "decision_confidence"]
            
            result = self.kernel.execute(
                "monitor",
                self.context,
                self.memory,
                target="validation_strategy",
                metrics=metrics,
                current_values={
                    "total_decisions": len(self.decisions),
                    "average_confidence": sum(d["confidence"] for d in self.decisions) / len(self.decisions) if self.decisions else 0.0
                }
            )
            
            if result.success and result.content:
                return {
                    "status": result.content.get("status", "unknown"),
                    "alerts": result.content.get("alerts", []),
                    "recommendations": result.content.get("recommendations", [])
                }
            
            return {"status": "unknown", "alerts": [], "recommendations": []}
        except Exception as e:
            logger.error(f"Optimization insights failed: {e}")
            return {"status": "error", "alerts": [], "recommendations": []}
    
    def _record_decision(self, decision_type: str, result: bool, confidence: float) -> None:
        """Record a decision for later reflection"""
        self.decisions.append({
            "type": decision_type,
            "result": result,
            "confidence": confidence
        })
    
    def _get_decision_summary(self) -> Dict[str, Any]:
        """Get summary of all decisions made during validation"""
        total = len(self.decisions)
        conditions_met = sum(1 for d in self.decisions if d["result"])
        avg_confidence = sum(d["confidence"] for d in self.decisions) / total if total > 0 else 0.0
        
        return {
            "total_decisions": total,
            "conditions_met": conditions_met,
            "average_confidence": avg_confidence
        }


class ReporterAgent:
    """
    Reporter Agent: Results compilation and reporting.
    
    Responsibilities:
    - Compile final report
    - Prioritize findings
    - Provide remediation guidance
    - Generate actionable recommendations
    
    Uses Brainary kernel for intelligent remediation recommendations.
    """
    
    def __init__(self, kernel: Optional[CognitiveKernel] = None, name: str = "SecurityReporter"):
        self.kernel = kernel or CognitiveKernel()
        self.name = name
        
        # Create agent config
        config = AgentConfig(
            name=name,
            role=AgentRole.WRITER,
            domain="security",
            description="Generates security reports and remediation guidance",
            quality_threshold=0.85,
            reasoning_style="practical"
        )
        self.agent = Agent.from_config(config)
        
        # Knowledge base
        self.kb = VulnerabilityKnowledgeBase()
        
        # Working memory for report context
        self.memory = WorkingMemory(capacity=8)
    
    def execute(self, context: ExecutionContext, 
                validated_findings: List[Dict]) -> Dict[str, Any]:
        """
        Generate final report.
        
        Args:
            context: Execution context
            validated_findings: Validated vulnerability findings
        
        Returns:
            Dictionary with report data
        """
        logger.info(f"ReporterAgent generating report for {len(validated_findings)} findings")
        
        # Add remediation recommendations
        findings_with_fixes = []
        for finding in validated_findings:
            fix = self._get_remediation(context, finding)
            if fix:
                finding["remediation"] = fix
            findings_with_fixes.append(finding)
        
        # Generate report
        report = self._generate_report(findings_with_fixes)
        
        logger.info("Report generation complete")
        
        return {
            "success": True,
            "report": report,
            "findings": findings_with_fixes,
            "summary": self._generate_executive_summary(findings_with_fixes)
        }
    
    def _get_remediation(self, context: ExecutionContext, 
                        finding: Dict) -> Optional[str]:
        """
        Get remediation recommendation using kernel orchestration.
        
        Routes through kernel to leverage:
        - Intelligent remediation strategies
        - Context-aware fix recommendations
        - Learning from successful fixes
        """
        # Extract vulnerability info
        cwe_id = finding.get("cwe_id")
        if not cwe_id:
            vulns = finding.get("vulnerabilities", [])
            if vulns:
                cwe_id = vulns[0].get("cwe_id")
        
        if not cwe_id:
            return None
        
        code = finding.get("context", "") or finding.get("match", "")
        if not code:
            return None
        
        # Prepare vulnerability for recommendation
        vulnerability = {"cwe_id": cwe_id}
        
        # Execute recommendation through kernel for intelligent routing
        # Kernel provides memory context, learns effective fixes, manages resources
        result = self.kernel.execute(
            "recommend_fix",
            context=context,
            working_memory=self.memory,
            vulnerability=vulnerability,
            code=code
        )
        
        if result.success:
            return result.output
        
        return None
    
    def _generate_report(self, findings: List[Dict]) -> str:
        """Generate detailed security report"""
        report = "=" * 80 + "\n"
        report += "JAVA SECURITY VULNERABILITY DETECTION REPORT\n"
        report += "=" * 80 + "\n\n"
        
        # Executive summary
        report += "EXECUTIVE SUMMARY\n"
        report += "-" * 80 + "\n"
        report += f"Total Vulnerabilities Found: {len(findings)}\n\n"
        
        # Count by severity
        severity_counts = {}
        for finding in findings:
            severity = finding.get("severity", "medium")
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        
        for severity in ["critical", "high", "medium", "low"]:
            count = severity_counts.get(severity, 0)
            if count > 0:
                report += f"  {severity.upper()}: {count}\n"
        
        report += "\n"
        
        # Detailed findings
        report += "DETAILED FINDINGS\n"
        report += "-" * 80 + "\n\n"
        
        for i, finding in enumerate(findings, 1):
            report += f"[{i}] "
            
            # Get CWE info
            cwe_id = finding.get("cwe_id", "UNKNOWN")
            pattern = self.kb.get_pattern(cwe_id)
            name = pattern.name if pattern else finding.get("name", "Unknown Vulnerability")
            
            report += f"{name} ({cwe_id})\n"
            report += f"    Severity: {finding.get('severity', 'UNKNOWN').upper()}\n"
            report += f"    Confidence: {finding.get('confidence', 'medium').upper()}\n"
            report += f"    Location: {finding.get('file', 'unknown')} line {finding.get('line', 0)}\n"
            
            if finding.get("analysis"):
                report += f"\n    Analysis:\n"
                # Truncate analysis if too long
                analysis = finding["analysis"][:500]
                report += f"    {analysis}\n"
            
            if finding.get("remediation"):
                report += f"\n    Remediation:\n"
                # Truncate remediation if too long
                remediation = finding["remediation"][:500]
                report += f"    {remediation}\n"
            
            report += "\n"
        
        report += "=" * 80 + "\n"
        report += "END OF REPORT\n"
        report += "=" * 80 + "\n"
        
        return report
    
    def _generate_executive_summary(self, findings: List[Dict]) -> str:
        """Generate executive summary"""
        summary = f"Found {len(findings)} confirmed vulnerabilities.\n\n"
        
        # Priority issues
        critical = [f for f in findings if f.get("severity") == "critical"]
        high = [f for f in findings if f.get("severity") == "high"]
        
        if critical:
            summary += f"CRITICAL: {len(critical)} critical vulnerabilities require immediate attention.\n"
        if high:
            summary += f"HIGH: {len(high)} high-severity issues should be addressed soon.\n"
        
        summary += "\nRecommended Actions:\n"
        summary += "1. Address all critical vulnerabilities immediately\n"
        summary += "2. Review and fix high-severity issues\n"
        summary += "3. Plan remediation for medium/low severity findings\n"
        
        return summary
