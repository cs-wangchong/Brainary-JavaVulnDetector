"""
Enhanced Security Primitives with Intelligent Control Flow

These primitives extend the base security primitives with intelligent
conditional logic, reflection, and monitoring capabilities.
"""

from typing import Any, Dict, List, Optional
import logging

from brainary.primitive.base import CorePrimitive, PrimitiveResult, CostMetrics, ConfidenceScore, ResourceEstimate
from brainary.core.context import ExecutionContext
from brainary.memory.working import WorkingMemory
from brainary.primitive import route_primitive

from .primitives import (
    ThinkSecurityPrimitive,
    DetectVulnerabilityPrimitive,
    ValidateFindingPrimitive,
    RecommendFixPrimitive
)
from .control_flow import SecurityControlFlow
from .knowledge import VulnerabilityKnowledgeBase

logger = logging.getLogger(__name__)


class EnhancedThinkSecurityPrimitive(ThinkSecurityPrimitive):
    """
    Enhanced security thinking with intelligent conditional logic.
    
    Uses conditional primitives to:
    - Decide analysis depth based on code patterns
    - Focus on high-risk areas
    - Skip analysis of safe patterns
    """
    
    def __init__(self):
        super().__init__()
        self.kb = VulnerabilityKnowledgeBase()
    
    def execute(self, context: ExecutionContext, working_memory: WorkingMemory, **kwargs) -> PrimitiveResult:
        """
        Enhanced security thinking with intelligent control flow.
        """
        code = kwargs.get('code') or kwargs.get('code_context', '')
        focus = kwargs.get('focus')
        
        # Create control flow helper
        control = SecurityControlFlow(context, working_memory)
        
        # Intelligent pre-analysis checks
        logger.debug("Performing intelligent pre-analysis...")
        
        # Check if code is in a test file (lower priority)
        file_path = kwargs.get('file_path', '')
        if control.conditional(
            "the file is a test file or test-related code",
            file_path=file_path,
            code_snippet=code[:200]  # First 200 chars
        ):
            logger.debug("Test file detected - using lightweight analysis")
            kwargs['reasoning_mode'] = 'fast'
        
        # Check if code has obvious security controls
        if control.has_security_controls(code, "input_validation"):
            logger.debug("Input validation detected - adjusting analysis focus")
            focus = "bypassing input validation"
        
        # Check for high-risk patterns that need deep analysis
        if control.conditional(
            "the code contains dangerous operations like file access, network calls, database queries, or command execution",
            code=code
        ):
            logger.debug("High-risk operations detected - enabling deep analysis")
            kwargs['reasoning_mode'] = 'deep'
        
        # Perform base analysis
        result = super().execute(context, working_memory, **kwargs)
        
        # Reflect on analysis quality
        if hasattr(result, 'content'):
            experience = {
                "code": code,
                "analysis": result.content,
                "confidence": result.confidence.score if hasattr(result, 'confidence') else 0.0
            }
            reflection = control.reflect(experience, focus="analysis_quality")
            
            # Add reflection insights to result
            if hasattr(result, 'metadata'):
                result.metadata['reflection'] = reflection
        
        return result


class EnhancedDetectVulnerabilityPrimitive(DetectVulnerabilityPrimitive):
    """
    Enhanced vulnerability detection with conditional analysis paths.
    
    Uses conditionals to:
    - Decide which detection methods to apply
    - Skip redundant checks
    - Focus on likely vulnerabilities
    """
    
    def execute(self, context: ExecutionContext, working_memory: WorkingMemory, **kwargs) -> PrimitiveResult:
        """
        Enhanced detection with intelligent conditional branching.
        """
        code = kwargs.get('code', '')
        vulnerability_type = kwargs.get('vulnerability_type', 'any')
        
        control = SecurityControlFlow(context, working_memory)
        
        # Intelligent detection path selection
        detection_methods = []
        
        # Conditional: Should we use pattern matching?
        if control.conditional(
            "pattern-based detection is likely to find vulnerabilities in this code",
            code=code,
            vulnerability_type=vulnerability_type
        ):
            detection_methods.append('pattern')
            logger.debug("Enabled pattern-based detection")
        
        # Conditional: Should we use semantic analysis?
        if control.conditional(
            "the code is complex and requires semantic analysis to understand data flow",
            code=code
        ):
            detection_methods.append('semantic')
            logger.debug("Enabled semantic analysis")
        
        # Conditional: Should we use LLM-based detection?
        if control.conditional(
            "the vulnerability requires understanding context and intent that only LLM can provide",
            code=code,
            vulnerability_type=vulnerability_type
        ):
            detection_methods.append('llm')
            logger.debug("Enabled LLM-based detection")
        
        # Update kwargs with selected methods
        kwargs['detection_methods'] = detection_methods
        
        # Perform base detection
        result = super().execute(context, working_memory, **kwargs)
        
        # Monitor detection quality
        monitoring = control.monitor(
            target="detection_effectiveness",
            metrics=["findings_count", "confidence", "method_coverage"]
        )
        
        if hasattr(result, 'metadata'):
            result.metadata['monitoring'] = monitoring
            result.metadata['detection_methods'] = detection_methods
        
        return result


class EnhancedValidateFindingPrimitive(ValidateFindingPrimitive):
    """
    Enhanced validation with intelligent conditional checks.
    
    Uses conditionals to:
    - Decide validation approach
    - Skip validation for obvious cases
    - Focus validation effort where needed
    """
    
    def execute(self, context: ExecutionContext, working_memory: WorkingMemory, **kwargs) -> PrimitiveResult:
        """
        Enhanced validation with intelligent control flow.
        """
        finding = kwargs.get('finding', {})
        code_context = kwargs.get('code_context', '')
        
        control = SecurityControlFlow(context, working_memory)
        
        # Quick validation checks using conditionals
        
        # Check 1: Is input validated?
        if code_context:
            input_var = self._extract_input_variable(finding)
            if input_var and control.is_input_validated(code_context, input_var):
                logger.debug(f"Input '{input_var}' appears validated - likely false positive")
                
                # Still run full validation but with adjusted prompt
                kwargs['validation_hint'] = f"Input '{input_var}' appears to be validated - check if validation is sufficient"
        
        # Check 2: Are there security controls?
        if control.has_security_controls(code_context, "authentication"):
            logger.debug("Authentication controls detected - check if they're bypassable")
            kwargs['validation_hint'] = kwargs.get('validation_hint', '') + " Code has authentication - verify if it's properly implemented"
        
        # Check 3: Is this a common false positive pattern?
        if control.conditional(
            "this finding matches common false positive patterns like logging statements or commented code",
            finding=finding,
            code=code_context
        ):
            logger.debug("Common false positive pattern detected")
            
            # Return early with false positive verdict
            return PrimitiveResult(
                content={
                    "is_valid": False,
                    "verdict": "False Positive: Common false positive pattern detected",
                    "confidence": 0.85,
                    "rationale": "Pattern analysis indicates this is a false positive"
                },
                confidence=ConfidenceScore(score=0.85, rationale="Pattern-based false positive detection"),
                cost=CostMetrics(tokens_used=50, time_ms=10, llm_calls=0),
                metadata={"validation_method": "pattern_based", "bypassed_llm": True}
            )
        
        # Check 4: Should we skip validation for high-confidence findings?
        severity = finding.get('severity', '').lower()
        if severity == 'critical' and control.conditional(
            "the finding has very clear indicators of being a true vulnerability with no ambiguity",
            finding=finding,
            code=code_context
        ):
            logger.debug("High-confidence critical finding - minimal validation needed")
            kwargs['validation_mode'] = 'lightweight'
        
        # Perform base validation
        result = super().execute(context, working_memory, **kwargs)
        
        # Reflect on validation accuracy
        experience = {
            "finding": finding,
            "validation_result": result.content if hasattr(result, 'content') else {},
            "code_context": code_context
        }
        reflection = control.reflect(experience, focus="validation_accuracy")
        
        if hasattr(result, 'metadata'):
            result.metadata['reflection'] = reflection
            result.metadata['control_flow_decisions'] = control.get_decision_summary()
        
        return result
    
    def _extract_input_variable(self, finding: Dict[str, Any]) -> Optional[str]:
        """Extract input variable name from finding."""
        description = finding.get('description', '').lower()
        
        # Common input variable names
        for var in ['input', 'request', 'param', 'parameter', 'data', 'value', 'query']:
            if var in description:
                return var
        
        return None


class EnhancedRecommendFixPrimitive(RecommendFixPrimitive):
    """
    Enhanced fix recommendation with context-aware suggestions.
    
    Uses conditionals to:
    - Tailor recommendations to code context
    - Consider existing security measures
    - Provide actionable, specific fixes
    """
    
    def execute(self, context: ExecutionContext, working_memory: WorkingMemory, **kwargs) -> PrimitiveResult:
        """
        Enhanced fix recommendation with intelligent context analysis.
        """
        finding = kwargs.get('finding', {})
        code_context = kwargs.get('code_context', '')
        
        control = SecurityControlFlow(context, working_memory)
        
        # Analyze context to provide better recommendations
        
        # Check for existing security libraries
        if control.conditional(
            "the code already uses security libraries like OWASP ESAPI, Apache Commons Validator, or Spring Security",
            code=code_context
        ):
            logger.debug("Security libraries detected - recommending library-based fixes")
            kwargs['recommendation_style'] = 'leverage_existing_libraries'
        
        # Check for framework-specific patterns
        if control.conditional(
            "the code uses Spring Framework",
            code=code_context
        ):
            logger.debug("Spring Framework detected")
            kwargs['framework'] = 'spring'
        elif control.conditional(
            "the code uses Jakarta EE or Java EE",
            code=code_context
        ):
            logger.debug("Jakarta EE detected")
            kwargs['framework'] = 'jakarta'
        
        # Check complexity level for appropriate recommendations
        if control.conditional(
            "the code is simple and straightforward without complex business logic",
            code=code_context
        ):
            kwargs['recommendation_complexity'] = 'simple'
        else:
            kwargs['recommendation_complexity'] = 'comprehensive'
        
        # Perform base recommendation
        result = super().execute(context, working_memory, **kwargs)
        
        # Monitor recommendation quality
        monitoring = control.monitor(
            target="recommendation_quality",
            metrics=["specificity", "actionability", "completeness"]
        )
        
        if hasattr(result, 'metadata'):
            result.metadata['monitoring'] = monitoring
            result.metadata['context_analysis'] = control.get_decision_summary()
        
        return result


def register_enhanced_primitives():
    """
    Register enhanced primitives with the router.
    
    Call this to override default security primitives with enhanced versions.
    """
    from brainary.primitive import register_implementation
    
    logger.info("Registering enhanced security primitives...")
    
    # Override with enhanced versions
    register_implementation("think_security", EnhancedThinkSecurityPrimitive())
    register_implementation("detect_vulnerability", EnhancedDetectVulnerabilityPrimitive())
    register_implementation("validate_finding", EnhancedValidateFindingPrimitive())
    register_implementation("recommend_fix", EnhancedRecommendFixPrimitive())
    
    logger.info("Enhanced security primitives registered successfully")
