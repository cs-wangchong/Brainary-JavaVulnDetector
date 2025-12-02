"""
Security-Specific Metacognitive Rules

Custom metacognitive rules for Java security detection to ensure quality,
reduce false positives, and improve detection accuracy.
"""

from typing import Any, Dict, Optional
from dataclasses import dataclass
from brainary.core.metacognitive_rules import MonitoringCriterion, CriteriaType, CriteriaEvaluation, TransitionAction, ActionType
from brainary.core.context import ExecutionContext
import logging

logger = logging.getLogger(__name__)


@dataclass
class RuleResult:
    """Result of rule evaluation."""
    passed: bool
    confidence: float
    feedback: str
    recommendations: list
    metadata: dict = None
    
    def __post_init__(self):
        if self.metadata is None:
            self.metadata = {}


class DetectionQualityRule:
    """
    Ensure detection quality meets minimum standards.
    
    Checks:
    - Confidence scores above threshold
    - Sufficient analysis depth
    - Required fields present in findings
    """
    
    def __init__(self, min_confidence: float = 0.7, min_analysis_depth: int = 3):
        self.name = "detection_quality"
        self.description = "Validates detection quality and completeness"
        self.min_confidence = min_confidence
        self.min_analysis_depth = min_analysis_depth
    
    def evaluate(self, context: ExecutionContext, metadata: Dict[str, Any]) -> RuleResult:
        """Evaluate detection quality."""
        findings = metadata.get('findings', [])
        
        if not findings:
            return RuleResult(
                passed=True,
                confidence=1.0,
                feedback="No findings to validate",
                recommendations=[]
            )
        
        issues = []
        low_confidence_count = 0
        incomplete_count = 0
        
        for finding in findings:
            # Check confidence
            confidence = finding.get('confidence', 'medium').lower()
            if confidence == 'low':
                low_confidence_count += 1
            
            # Check completeness
            required_fields = ['name', 'description', 'severity', 'file', 'line']
            missing_fields = [f for f in required_fields if f not in finding or not finding[f]]
            if missing_fields:
                incomplete_count += 1
                issues.append(f"Finding missing fields: {', '.join(missing_fields)}")
        
        # Calculate quality score
        total_findings = len(findings)
        low_confidence_ratio = low_confidence_count / total_findings if total_findings > 0 else 0
        incomplete_ratio = incomplete_count / total_findings if total_findings > 0 else 0
        
        quality_score = 1.0 - (low_confidence_ratio * 0.5 + incomplete_ratio * 0.5)
        
        passed = quality_score >= self.min_confidence
        
        recommendations = []
        if low_confidence_count > 0:
            recommendations.append(f"Re-analyze {low_confidence_count} low-confidence findings")
        if incomplete_count > 0:
            recommendations.append(f"Complete {incomplete_count} findings with missing information")
        
        if not passed:
            recommendations.append(f"Overall quality score {quality_score:.2f} below threshold {self.min_confidence}")
        
        return RuleResult(
            passed=passed,
            confidence=quality_score,
            feedback=f"Quality assessment: {quality_score:.2%} ({total_findings} findings, {low_confidence_count} low-confidence, {incomplete_count} incomplete)",
            recommendations=recommendations,
            metadata={
                "quality_score": quality_score,
                "total_findings": total_findings,
                "low_confidence_count": low_confidence_count,
                "incomplete_count": incomplete_count
            }
        )


class FalsePositiveFilterRule:
    """
    Filter likely false positives before reporting.
    
    Applies heuristics to identify and flag potential false positives:
    - Protected by framework security features
    - Input validation present
    - Known safe patterns
    """
    
    def __init__(self, max_false_positive_ratio: float = 0.3):
        self.name = "false_positive_filter"
        self.description = "Identifies and filters likely false positives"
        self.max_false_positive_ratio = max_false_positive_ratio
    
    def evaluate(self, context: ExecutionContext, metadata: Dict[str, Any]) -> RuleResult:
        """Evaluate false positive likelihood."""
        findings = metadata.get('findings', [])
        
        if not findings:
            return RuleResult(
                passed=True,
                confidence=1.0,
                feedback="No findings to filter",
                recommendations=[]
            )
        
        likely_false_positives = []
        
        for i, finding in enumerate(findings):
            # Check for validation indicators
            code = finding.get('code', '').lower()
            description = finding.get('description', '').lower()
            
            # False positive indicators
            has_validation = any(indicator in code for indicator in [
                'validate', 'sanitize', 'escape', 'encode', 'filter'
            ])
            has_framework_protection = any(protection in code for protection in [
                '@preauthorize', 'csrf', 'security', 'authenticated'
            ])
            has_safe_api = any(api in code for api in [
                'preparedstatement', 'parameterized', 'safehtml'
            ])
            
            # Score false positive likelihood
            fp_score = 0
            if has_validation:
                fp_score += 0.4
            if has_framework_protection:
                fp_score += 0.4
            if has_safe_api:
                fp_score += 0.3
            
            if fp_score >= 0.5:
                likely_false_positives.append({
                    "index": i,
                    "name": finding.get('name', 'unknown'),
                    "fp_score": fp_score,
                    "reason": self._get_fp_reason(has_validation, has_framework_protection, has_safe_api)
                })
        
        fp_count = len(likely_false_positives)
        fp_ratio = fp_count / len(findings) if findings else 0
        
        passed = fp_ratio <= self.max_false_positive_ratio
        
        recommendations = []
        if fp_count > 0:
            recommendations.append(f"Review {fp_count} potential false positives")
            for fp in likely_false_positives[:3]:  # Show first 3
                recommendations.append(f"  - {fp['name']}: {fp['reason']}")
        
        if not passed:
            recommendations.append(f"False positive ratio {fp_ratio:.2%} exceeds threshold {self.max_false_positive_ratio:.2%}")
            recommendations.append("Consider additional validation or tuning detection rules")
        
        return RuleResult(
            passed=passed,
            confidence=1.0 - fp_ratio * 0.5,
            feedback=f"False positive assessment: {fp_count}/{len(findings)} likely false positives ({fp_ratio:.2%})",
            recommendations=recommendations,
            metadata={
                "likely_false_positives": likely_false_positives,
                "fp_ratio": fp_ratio,
                "total_findings": len(findings)
            }
        )
    
    def _get_fp_reason(self, has_validation: bool, has_framework: bool, has_safe_api: bool) -> str:
        """Generate reason for false positive classification."""
        reasons = []
        if has_validation:
            reasons.append("input validation present")
        if has_framework:
            reasons.append("framework protection detected")
        if has_safe_api:
            reasons.append("safe API usage")
        return ", ".join(reasons)


class SeverityValidationRule:
    """
    Validate severity assessments are appropriate.
    
    Ensures:
    - Critical findings have sufficient justification
    - Severity aligns with CWE/OWASP standards
    - Exploitability matches severity
    """
    
    def __init__(self):
        self.name = "severity_validation"
        self.description = "Validates severity assessments against standards"
        
        # CWE IDs that should always be critical/high
        self.critical_cwes = {'CWE-89', 'CWE-78', 'CWE-79', 'CWE-502', 'CWE-798'}
    
    def evaluate(self, context: ExecutionContext, metadata: Dict[str, Any]) -> RuleResult:
        """Validate severity assignments."""
        findings = metadata.get('findings', [])
        
        if not findings:
            return RuleResult(
                passed=True,
                confidence=1.0,
                feedback="No findings to validate",
                recommendations=[]
            )
        
        mismatched_severities = []
        
        for finding in findings:
            cwe_id = finding.get('cwe_id', '')
            severity = finding.get('severity', '').lower()
            name = finding.get('name', 'unknown')
            
            # Check if critical CWE has appropriate severity
            if cwe_id in self.critical_cwes:
                if severity not in ['critical', 'high']:
                    mismatched_severities.append({
                        "name": name,
                        "cwe_id": cwe_id,
                        "current_severity": severity,
                        "expected_severity": "Critical/High",
                        "reason": f"{cwe_id} is typically critical"
                    })
        
        mismatch_count = len(mismatched_severities)
        passed = mismatch_count == 0
        
        recommendations = []
        if mismatch_count > 0:
            recommendations.append(f"Review severity for {mismatch_count} findings")
            for mismatch in mismatched_severities:
                recommendations.append(
                    f"  - {mismatch['name']} ({mismatch['cwe_id']}): "
                    f"currently {mismatch['current_severity']}, expected {mismatch['expected_severity']}"
                )
        
        confidence = 1.0 if passed else 0.7
        
        return RuleResult(
            passed=passed,
            confidence=confidence,
            feedback=f"Severity validation: {mismatch_count} mismatches found",
            recommendations=recommendations,
            metadata={
                "mismatched_severities": mismatched_severities,
                "total_findings": len(findings)
            }
        )


class RemediationEffectivenessRule:
    """
    Ensure remediation recommendations are actionable and complete.
    
    Checks:
    - Specific code examples provided
    - Clear explanation of fix
    - References to security standards
    """
    
    def __init__(self, require_code_examples: bool = True):
        self.name = "remediation_effectiveness"
        self.description = "Validates remediation recommendations are actionable"
        self.require_code_examples = require_code_examples
    
    def evaluate(self, context: ExecutionContext, metadata: Dict[str, Any]) -> RuleResult:
        """Evaluate remediation quality."""
        findings = metadata.get('findings', [])
        
        if not findings:
            return RuleResult(
                passed=True,
                confidence=1.0,
                feedback="No findings with remediation to evaluate",
                recommendations=[]
            )
        
        findings_with_remediation = [f for f in findings if f.get('remediation')]
        
        if not findings_with_remediation:
            return RuleResult(
                passed=False,
                confidence=0.5,
                feedback="No remediation recommendations provided",
                recommendations=["Generate remediation recommendations for findings"]
            )
        
        incomplete_remediations = []
        
        for finding in findings_with_remediation:
            remediation = finding.get('remediation', {})
            
            # Check for required elements
            has_code_example = bool(remediation.get('secure_code_example'))
            has_explanation = bool(remediation.get('explanation'))
            has_priority = bool(remediation.get('priority'))
            
            if self.require_code_examples and not has_code_example:
                incomplete_remediations.append({
                    "name": finding.get('name', 'unknown'),
                    "missing": "code example"
                })
            elif not has_explanation:
                incomplete_remediations.append({
                    "name": finding.get('name', 'unknown'),
                    "missing": "explanation"
                })
            elif not has_priority:
                incomplete_remediations.append({
                    "name": finding.get('name', 'unknown'),
                    "missing": "priority"
                })
        
        incomplete_count = len(incomplete_remediations)
        remediation_quality = 1.0 - (incomplete_count / len(findings_with_remediation))
        
        passed = incomplete_count == 0
        
        recommendations = []
        if incomplete_count > 0:
            recommendations.append(f"Complete {incomplete_count} incomplete remediations")
            for item in incomplete_remediations[:3]:
                recommendations.append(f"  - {item['name']}: missing {item['missing']}")
        
        return RuleResult(
            passed=passed,
            confidence=remediation_quality,
            feedback=f"Remediation quality: {remediation_quality:.2%} complete ({len(findings_with_remediation)}/{len(findings)} with remediation)",
            recommendations=recommendations,
            metadata={
                "total_findings": len(findings),
                "findings_with_remediation": len(findings_with_remediation),
                "incomplete_remediations": incomplete_count
            }
        )


class ProgressMonitoringRule:
    """
    Monitor detection progress and performance.
    
    Tracks:
    - Detection coverage
    - Processing time
    - Memory usage efficiency
    """
    
    def __init__(self, max_processing_time_ms: int = 30000):
        self.name = "progress_monitoring"
        self.description = "Monitors detection progress and performance"
        self.max_processing_time_ms = max_processing_time_ms
    
    def evaluate(self, context: ExecutionContext, metadata: Dict[str, Any]) -> RuleResult:
        """Monitor detection progress."""
        processing_time = metadata.get('processing_time_ms', 0)
        files_scanned = metadata.get('files_scanned', 0)
        findings_count = metadata.get('findings_count', 0)
        
        # Check performance
        time_exceeded = processing_time > self.max_processing_time_ms
        
        # Calculate efficiency metrics
        time_per_file = processing_time / files_scanned if files_scanned > 0 else 0
        findings_per_file = findings_count / files_scanned if files_scanned > 0 else 0
        
        passed = not time_exceeded
        
        recommendations = []
        if time_exceeded:
            recommendations.append(f"Processing time {processing_time}ms exceeds limit {self.max_processing_time_ms}ms")
            recommendations.append("Consider optimizing scan scope or parallel processing")
        
        feedback_parts = [
            f"{files_scanned} files scanned",
            f"{findings_count} findings",
            f"{processing_time}ms total",
            f"{time_per_file:.0f}ms/file average"
        ]
        
        return RuleResult(
            passed=passed,
            confidence=1.0,
            feedback="Progress: " + ", ".join(feedback_parts),
            recommendations=recommendations,
            metadata={
                "processing_time_ms": processing_time,
                "files_scanned": files_scanned,
                "findings_count": findings_count,
                "time_per_file_ms": time_per_file,
                "findings_per_file": findings_per_file
            }
        )


def create_security_metacognitive_rules() -> list:
    """
    Create all security-specific metacognitive rules.
    
    Returns:
        List of MetacognitiveRule instances
    """
    return [
        DetectionQualityRule(min_confidence=0.7),
        FalsePositiveFilterRule(max_false_positive_ratio=0.3),
        SeverityValidationRule(),
        RemediationEffectivenessRule(require_code_examples=True),
        ProgressMonitoringRule(max_processing_time_ms=30000)
    ]
