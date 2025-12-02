"""
Java Security Vulnerability Detector (Redesigned)

Simplified detector using TemplateAgent-based SecurityDetectorAgent.
This replaces the old multi-agent architecture with a single intelligent agent.
"""

from typing import Any, Dict, List, Optional
from pathlib import Path
from dataclasses import dataclass
import json
import logging

from .security_agent import SecurityDetectorAgent

logger = logging.getLogger(__name__)


@dataclass
class DetectionConfig:
    """Configuration for detection process."""
    deep_analysis: bool = True
    validate_findings: bool = True
    generate_remediation: bool = True
    max_findings: int = 50
    focus_areas: Optional[List[str]] = None
    confidence_threshold: str = "medium"  # low/medium/high


class JavaSecurityDetector:
    """
    Intelligent Java vulnerability detector (redesigned).
    
    Now uses single SecurityDetectorAgent (TemplateAgent subclass) with:
    - Custom security primitives
    - Semantic memory with OWASP/CWE knowledge
    - Metacognitive rules for quality assurance
    - Comprehensive detection pipeline in process() method
    
    Usage:
        detector = JavaSecurityDetector()
        result = detector.detect("/path/to/java/project")
        
        # Access findings
        findings = result['findings']
        summary = result['summary']
        
        # View statistics
        stats = detector.get_stats()
    """
    
    def __init__(self, config: Optional[DetectionConfig] = None):
        """
        Initialize detector.
        
        Args:
            config: Detection configuration
        """
        self.config = config or DetectionConfig()
        
        # Create single security detector agent
        self.agent = SecurityDetectorAgent(name="JavaSecurityDetector")
        
        logger.info("JavaSecurityDetector initialized with SecurityDetectorAgent")
    
    def detect(self, target: str, config: Optional[DetectionConfig] = None) -> Dict[str, Any]:
        """
        Run complete vulnerability detection pipeline.
        
        Args:
            target: File or directory to analyze
            config: Optional detection configuration (overrides default)
        
        Returns:
            Dictionary with complete detection results:
            {
                "target": str,
                "findings": List[Dict],
                "findings_count": int,
                "summary": str,
                "statistics": Dict,
                "processing_time_ms": int,
                "success": bool
            }
        """
        config = config or self.config
        
        logger.info(f"Starting detection for: {target}")
        
        # Validate target
        target_path = Path(target)
        if not target_path.exists():
            return {
                "success": False,
                "error": f"Target not found: {target}",
                "findings": [],
                "findings_count": 0
            }
        
        # Run agent detection pipeline
        result = self.agent.run(
            target,
            deep_analysis=config.deep_analysis,
            validate=config.validate_findings,
            remediate=config.generate_remediation,
            max_findings=config.max_findings
        )
        
        if not result.success:
            logger.error(f"Detection failed: {result.content.get('error_message', 'Unknown error')}")
            return {
                "success": False,
                "error": result.content.get('error_message', 'Detection pipeline failed'),
                "findings": [],
                "findings_count": 0
            }
        
        # Extract results
        detection_result = {
            "success": True,
            "target": result.content.get('target', target),
            "findings": result.content.get('findings', []),
            "findings_count": result.content.get('findings_count', 0),
            "summary": result.content.get('summary', ''),
            "statistics": result.content.get('statistics', {}),
            "processing_time_ms": result.content.get('processing_time_ms', 0)
        }
        
        logger.info(f"Detection complete: {detection_result['findings_count']} findings")
        
        return detection_result
    
    def detect_file(self, file_path: str, **kwargs) -> Dict[str, Any]:
        """
        Detect vulnerabilities in a single file.
        
        Args:
            file_path: Path to Java file
            **kwargs: Additional detection options
        
        Returns:
            Detection result dictionary
        """
        return self.detect(file_path, **kwargs)
    
    def detect_directory(self, dir_path: str, **kwargs) -> Dict[str, Any]:
        """
        Detect vulnerabilities in all Java files in a directory.
        
        Args:
            dir_path: Path to directory
            **kwargs: Additional detection options
        
        Returns:
            Detection result dictionary
        """
        return self.detect(dir_path, **kwargs)
    
    def get_stats(self) -> Dict[str, Any]:
        """
        Get detection statistics.
        
        Returns:
            Statistics dictionary with:
            - total_scans: Number of detection runs
            - total_findings: Total vulnerabilities found
            - validated_findings: Findings that passed validation
            - false_positives_filtered: False positives removed
            - remediations_generated: Fixes recommended
            - agent_stats: Agent-level statistics
        """
        return self.agent.get_detection_stats()
    
    def get_memory_summary(self) -> Dict[str, Any]:
        """
        Get summary of what the agent has learned.
        
        Returns:
            Memory summary with episodic and semantic knowledge
        """
        # Get recent detections from episodic memory (stored as ConceptualKnowledge)
        from brainary.memory.semantic import KnowledgeType
        recent_detections = self.agent.semantic_memory.search(
            query="detection episode",
            knowledge_types=[KnowledgeType.CONCEPTUAL],
            top_k=5
        )
        
        # Get knowledge stats
        semantic_knowledge = self.agent.semantic_memory.search(
            query="vulnerability",
            knowledge_types=[KnowledgeType.FACTUAL],
            top_k=10
        )
        
        procedural_knowledge = self.agent.semantic_memory.search(
            query="remediation",
            knowledge_types=[KnowledgeType.PROCEDURAL],
            top_k=5
        )
        
        # Extract detection summaries from ConceptualKnowledge entries
        detection_summaries = []
        for item in recent_detections:
            # ConceptualKnowledge has description and metadata, not content
            summary = {
                "description": item.description,
                "key_concepts": item.key_concepts,
                "metadata": item.metadata
            }
            detection_summaries.append(summary)
        
        # Count working memory items across all tiers
        l1_count = len(self.agent.working_memory._l1_items)
        l2_count = len(self.agent.working_memory._l2_items)
        l3_count = len(self.agent.working_memory._l3_items)
        total_working = l1_count + l2_count + l3_count
        
        return {
            "recent_detections": detection_summaries,
            "semantic_knowledge_count": len(semantic_knowledge),
            "procedural_knowledge_count": len(procedural_knowledge),
            "working_memory_items": total_working
        }
    
    def export_report(self, result: Dict[str, Any], output_file: str, 
                     format: str = "json") -> None:
        """
        Export detection report to file.
        
        Args:
            result: Detection result from detect()
            output_file: Output file path
            format: Report format ("json" or "md")
        """
        output_path = Path(output_file)
        
        if format == "json":
            with open(output_path, 'w') as f:
                json.dump(result, f, indent=2, default=str)
            logger.info(f"JSON report exported to: {output_path}")
            
        elif format == "md":
            markdown = self._generate_markdown_report(result)
            with open(output_path, 'w') as f:
                f.write(markdown)
            logger.info(f"Markdown report exported to: {output_path}")
            
        else:
            raise ValueError(f"Unsupported format: {format}")
    
    def _generate_markdown_report(self, result: Dict[str, Any]) -> str:
        """Generate markdown report from detection result."""
        findings = result.get('findings', [])
        target = result.get('target', 'Unknown')
        processing_time = result.get('processing_time_ms', 0)
        
        # Count by severity
        critical = len([f for f in findings if f.get('severity', '').lower() == 'critical'])
        high = len([f for f in findings if f.get('severity', '').lower() == 'high'])
        medium = len([f for f in findings if f.get('severity', '').lower() == 'medium'])
        low = len([f for f in findings if f.get('severity', '').lower() == 'low'])
        
        lines = [
            "# Java Security Detection Report",
            "",
            f"**Target:** `{target}`",
            f"**Generated:** {result.get('timestamp', 'N/A')}",
            f"**Processing Time:** {processing_time}ms",
            "",
            "## Summary",
            "",
            f"- **Total Findings:** {len(findings)}",
            f"- **Critical:** {critical}",
            f"- **High:** {high}",
            f"- **Medium:** {medium}",
            f"- **Low:** {low}",
            "",
            "## Findings",
            ""
        ]
        
        for i, finding in enumerate(findings, 1):
            name = finding.get('name', 'Unknown')
            severity = finding.get('severity', 'Unknown')
            file_path = finding.get('file', 'unknown')
            line_num = finding.get('line', '?')
            description = finding.get('description', 'No description')
            
            lines.extend([
                f"### {i}. {name}",
                "",
                f"**Severity:** {severity}",
                f"**Location:** `{file_path}:{line_num}`",
                f"**CWE:** {finding.get('cwe_id', 'N/A')}",
                "",
                f"**Description:**",
                description,
                ""
            ])
            
            # Add code snippet if available
            code = finding.get('match', '') or finding.get('snippet', '')
            if code:
                lines.extend([
                    "**Vulnerable Code:**",
                    "```java",
                    code,
                    "```",
                    ""
                ])
            
            # Add remediation if available
            remediation = finding.get('remediation', {})
            if remediation:
                lines.extend([
                    "**Remediation:**",
                    f"Priority: {remediation.get('priority', 'N/A')}",
                    "",
                    remediation.get('fix_summary', ''),
                    ""
                ])
                
                if remediation.get('secure_code_example'):
                    lines.extend([
                        "**Secure Code Example:**",
                        "```java",
                        remediation.get('secure_code_example', ''),
                        "```",
                        ""
                    ])
            
            lines.append("---")
            lines.append("")
        
        # Add statistics
        stats = result.get('statistics', {})
        if stats:
            lines.extend([
                "## Detection Statistics",
                "",
                f"- Total Scans: {stats.get('total_scans', 0)}",
                f"- Total Findings: {stats.get('total_findings', 0)}",
                f"- Validated Findings: {stats.get('validated_findings', 0)}",
                f"- False Positives Filtered: {stats.get('false_positives_filtered', 0)}",
                f"- Remediations Generated: {stats.get('remediations_generated', 0)}",
                ""
            ])
        
        return "\n".join(lines)
    
    def reset_stats(self) -> None:
        """Reset detection statistics."""
        self.agent.reset_stats()
        logger.info("Detection statistics reset")


# Convenience function for quick detection
def detect_vulnerabilities(target: str, **kwargs) -> Dict[str, Any]:
    """
    Quick vulnerability detection function.
    
    Args:
        target: File or directory to scan
        **kwargs: Detection options
    
    Returns:
        Detection result dictionary
    
    Example:
        result = detect_vulnerabilities("/path/to/project")
        print(f"Found {result['findings_count']} vulnerabilities")
    """
    detector = JavaSecurityDetector()
    return detector.detect(target, **kwargs)
