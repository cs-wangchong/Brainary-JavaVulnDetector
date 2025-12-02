"""
Intelligent Control Flow for Security Detection

Leverages Brainary's built-in control flow primitives (conditional, reflect, monitor)
to create adaptive, self-improving detection logic.

Uses existing Brainary primitives:
- conditional (from brainary.primitive.implementations.control.conditional)
- reflect (from brainary.primitive.implementations.metacognitive.reflect)
- monitor (from brainary.primitive.implementations.core.monitor)
"""

from typing import Any, Dict, List, Optional, Callable
from dataclasses import dataclass
import logging

from brainary.core.context import ExecutionContext
from brainary.memory.working import WorkingMemory
from brainary.core.kernel import CognitiveKernel

logger = logging.getLogger(__name__)


@dataclass
class AnalysisDecision:
    """Decision made during analysis"""
    condition: str
    result: bool
    confidence: float
    rationale: str
    branch_taken: str


class SecurityControlFlow:
    """
    Intelligent control flow for security detection using Brainary's built-in primitives.
    
    Uses Brainary's conditional, reflect, and monitor primitives to create adaptive
    detection logic that learns from its decisions.
    
    This is a convenience wrapper around Brainary's kernel execution to make
    it easy to use control flow primitives for security detection.
    """
    
    def __init__(self, context: ExecutionContext, memory: WorkingMemory, kernel: Optional[CognitiveKernel] = None):
        self.context = context
        self.memory = memory
        self.kernel = kernel or CognitiveKernel()
        self.decisions: List[AnalysisDecision] = []
    
    def conditional(self, condition: str, **context_data) -> bool:
        """
        Intelligent conditional check using Brainary's built-in conditional primitive
        with built-in LLM-based semantic evaluation.
        
        The conditional primitive now handles semantic evaluation internally,
        supporting both simple boolean conditions and complex natural language conditions.
        
        Args:
            condition: Condition to evaluate (simple or complex natural language)
            **context_data: Context for condition evaluation
        
        Returns:
            Boolean result of condition evaluation
        
        Examples:
            # Simple condition
            conditional("true")
            
            # Semantic condition
            conditional(
                "the code contains SQL injection vulnerability",
                code=code_snippet,
                file_path=path
            )
        """
        try:
            # Use kernel to execute conditional primitive
            # The primitive now handles semantic evaluation internally
            result = self.kernel.execute(
                "conditional",
                self.context,
                self.memory,
                condition=condition,
                if_true="true",
                if_false="false",
                **context_data
            )
            
            # Extract decision from result
            if result.success and result.content:
                content = result.content
                # The conditional primitive returns condition_result
                if isinstance(content, dict):
                    decision = content.get('condition_result', False)
                    evaluation_method = content.get('evaluation_method', 'unknown')
                else:
                    decision = bool(content)
                    evaluation_method = 'unknown'
            else:
                decision = False
                evaluation_method = 'error'
            
            # Extract confidence
            confidence = result.confidence.overall if hasattr(result, 'confidence') else 0.8
            
            # Record decision for reflection
            self.decisions.append(AnalysisDecision(
                condition=condition,
                result=bool(decision),
                confidence=confidence,
                rationale=f"{evaluation_method}: {str(context_data)}",
                branch_taken='then' if decision else 'else'
            ))
            
            logger.debug(f"Condition '{condition[:50]}...' evaluated to {decision} via {evaluation_method} (confidence: {confidence:.2f})")
            
            return bool(decision)
        
        except Exception as e:
            logger.error(f"Conditional evaluation failed: {e}")
            # Default to conservative behavior (assume condition is true for security)
            return True
    
    def reflect(self, experience: Dict[str, Any], focus: str = "effectiveness") -> Dict[str, Any]:
        """
        Reflect on detection experience using Brainary's built-in reflect primitive.
        
        Args:
            experience: Dictionary describing the experience to reflect on
            focus: What aspect to focus reflection on
        
        Returns:
            Dictionary with insights and lessons learned
        """
        try:
            # Use kernel to execute reflect primitive
            result = self.kernel.execute(
                "reflect",
                self.context,
                self.memory,
                experience=experience,
                focus=focus
            )
            
            if result.success and result.content:
                # The reflect primitive returns structured reflection
                return result.content
            return {"insights": [], "lessons": []}
        
        except Exception as e:
            logger.error(f"Reflection failed: {e}")
            return {"insights": [], "lessons": []}
    
    def monitor(self, target: str, metrics: List[str], **kwargs) -> Dict[str, Any]:
        """
        Monitor analysis progress and quality using Brainary's built-in monitor primitive.
        
        Args:
            target: What to monitor (e.g., "analysis_quality", "false_positive_rate")
            metrics: List of metrics to track
            **kwargs: Additional monitoring parameters (current_values, thresholds)
        
        Returns:
            Dictionary with monitoring results
        """
        try:
            # Use kernel to execute monitor primitive
            result = self.kernel.execute(
                "monitor",
                self.context,
                self.memory,
                target=target,
                metrics=metrics,
                **kwargs
            )
            
            if result.success and result.content:
                # The monitor primitive returns structured monitoring snapshot
                return result.content
            return {"status": "unknown", "alerts": []}
        
        except Exception as e:
            logger.error(f"Monitoring failed: {e}")
            return {"status": "unknown", "alerts": []}
    
    def should_analyze_deeply(self, finding: Dict[str, Any]) -> bool:
        """
        Decide if finding requires deep analysis using intelligent conditions.
        
        Args:
            finding: Finding to evaluate
        
        Returns:
            True if deep analysis recommended
        """
        # Check severity first
        severity = finding.get("severity", "medium").lower()
        
        if self.conditional(
            "the severity is critical or high",
            severity=severity,
            description=finding.get("description", "")
        ):
            logger.debug(f"Deep analysis: High severity ({severity})")
            return True
        
        # Check if it's a well-known vulnerability pattern
        if self.conditional(
            "the vulnerability is a well-known dangerous pattern like SQL injection, XXE, or deserialization",
            description=finding.get("description", ""),
            cwe_id=finding.get("cwe_id", "")
        ):
            logger.debug(f"Deep analysis: Dangerous pattern")
            return True
        
        # Check if code context suggests real vulnerability
        code = finding.get("code_snippet", "")
        if code and self.conditional(
            "the code snippet contains user input handling without proper sanitization or validation",
            code=code,
            file_path=finding.get("file", "")
        ):
            logger.debug(f"Deep analysis: Unsanitized input detected")
            return True
        
        return False
    
    def should_skip_validation(self, finding: Dict[str, Any], analysis: Optional[Dict] = None) -> bool:
        """
        Decide if validation can be skipped (high confidence finding).
        
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
        if analysis and self.conditional(
            "the analysis clearly shows this is a false positive with no exploitable path",
            analysis_result=analysis.get("analysis", ""),
            confidence=analysis.get("confidence", 0.0)
        ):
            logger.debug("Skipping validation: Clear false positive")
            return True
        
        return False
    
    def is_input_validated(self, code_context: str, variable_name: str = "input") -> bool:
        """
        Check if input is validated in the code context.
        
        This is a key example of using conditional for fine-grained analysis.
        
        Args:
            code_context: Code to analyze
            variable_name: Variable to check for validation
        
        Returns:
            True if input appears to be validated
        """
        return self.conditional(
            f"the {variable_name} parameter is validated or sanitized by the code",
            code=code_context,
            variable=variable_name
        )
    
    def has_security_controls(self, code_context: str, control_type: str = "any") -> bool:
        """
        Check if code has security controls in place.
        
        Args:
            code_context: Code to analyze
            control_type: Type of control to look for (e.g., "authentication", "authorization", "input_validation")
        
        Returns:
            True if security controls are present
        """
        return self.conditional(
            f"the code implements {control_type} security controls",
            code=code_context,
            control_type=control_type
        )
    
    def should_retry_analysis(self, finding: Dict[str, Any], attempt: int, max_attempts: int = 3) -> bool:
        """
        Decide if analysis should be retried.
        
        Args:
            finding: Finding that failed analysis
            attempt: Current attempt number
            max_attempts: Maximum attempts allowed
        
        Returns:
            True if should retry
        """
        if attempt >= max_attempts:
            return False
        
        # Retry high-priority findings
        if self.conditional(
            "the finding is high priority and warrants another analysis attempt",
            finding=finding,
            attempt=attempt
        ):
            logger.info(f"Retrying analysis (attempt {attempt + 1}/{max_attempts})")
            return True
        
        return False
    
    def assess_confidence(self, finding: Dict[str, Any], analysis: Optional[Dict] = None) -> float:
        """
        Assess confidence level in finding using reflection.
        
        Args:
            finding: Finding to assess
            analysis: Optional analysis result
        
        Returns:
            Confidence score (0.0 - 1.0)
        """
        # Use reflect primitive to assess confidence based on experience
        experience = {
            "finding": finding,
            "analysis": analysis,
            "decisions": self.decisions[-5:] if self.decisions else []  # Recent decisions
        }
        
        reflection = self.reflect(experience, focus="confidence_assessment")
        
        # Extract confidence from reflection
        insights = reflection.get("insights", [])
        if insights:
            # Try to parse confidence from insights
            for insight in insights:
                if "confidence" in str(insight).lower():
                    try:
                        # Look for numeric confidence score
                        words = str(insight).split()
                        for word in words:
                            if word.replace(".", "").isdigit():
                                score = float(word)
                                if 0 <= score <= 1:
                                    return score
                                elif 0 <= score <= 100:
                                    return score / 100
                    except:
                        pass
        
        # Default to moderate confidence
        return 0.7
    
    def get_decision_summary(self) -> Dict[str, Any]:
        """
        Get summary of all decisions made during detection.
        
        Returns:
            Dictionary with decision statistics and insights
        """
        if not self.decisions:
            return {"total": 0, "insights": []}
        
        total = len(self.decisions)
        true_conditions = sum(1 for d in self.decisions if d.result)
        avg_confidence = sum(d.confidence for d in self.decisions) / total
        
        return {
            "total_decisions": total,
            "conditions_met": true_conditions,
            "conditions_not_met": total - true_conditions,
            "average_confidence": avg_confidence,
            "recent_decisions": [
                {
                    "condition": d.condition,
                    "result": d.result,
                    "confidence": d.confidence,
                    "branch": d.branch_taken
                }
                for d in self.decisions[-10:]
            ]
        }
    
    def optimize_detection_strategy(self) -> Dict[str, Any]:
        """
        Use reflection to optimize detection strategy based on experience.
        
        Returns:
            Dictionary with optimization recommendations
        """
        experience = {
            "decisions": self.decisions,
            "summary": self.get_decision_summary()
        }
        
        reflection = self.reflect(experience, focus="strategy_optimization")
        
        return {
            "insights": reflection.get("insights", []),
            "recommendations": reflection.get("lessons", []),
            "decision_summary": self.get_decision_summary()
        }


class AdaptiveAnalysisStrategy:
    """
    Adaptive analysis strategy that learns from feedback.
    
    Uses Brainary's monitor and reflect primitives to continuously improve.
    """
    
    def __init__(self, context: ExecutionContext, memory: WorkingMemory, kernel: Optional[CognitiveKernel] = None):
        self.control_flow = SecurityControlFlow(context, memory, kernel)
        self.analysis_history: List[Dict] = []
    
    def analyze_with_adaptation(self, finding: Dict[str, Any], analysis_fn: Callable) -> Dict[str, Any]:
        """
        Analyze finding with adaptive strategy.
        
        Args:
            finding: Finding to analyze
            analysis_fn: Function to perform analysis
        
        Returns:
            Analysis result
        """
        # Monitor analysis quality
        monitoring = self.control_flow.monitor(
            target="analysis_quality",
            metrics=["success_rate", "false_positive_rate", "confidence"]
        )
        
        # Decide on analysis depth
        deep_analysis = self.control_flow.should_analyze_deeply(finding)
        
        # Perform analysis
        result = analysis_fn(finding, deep=deep_analysis)
        
        # Record experience
        self.analysis_history.append({
            "finding": finding,
            "result": result,
            "deep_analysis": deep_analysis,
            "monitoring": monitoring
        })
        
        # Reflect periodically to improve
        if len(self.analysis_history) % 10 == 0:
            optimization = self.control_flow.optimize_detection_strategy()
            logger.info(f"Strategy optimization: {optimization.get('recommendations', [])}")
        
        return result
