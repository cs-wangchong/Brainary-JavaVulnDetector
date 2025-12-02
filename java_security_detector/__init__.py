"""
Java Security Vulnerability Detection Domain

An intelligent, autonomous vulnerability detection system for Java applications,
powered by Brainary cognitive architecture. Combines LLM reasoning with
static analysis tools (CodeQL) for accurate, context-aware security analysis.

Key Features:
- Multi-agent detection system (Scanner, Analyzer, Validator, Reporter)
- Domain-specific primitives (AnalyzeCode, DetectVulnerability, ThinkSecurity, ValidateFinding, RecommendFix)
- CodeQL integration as agent tool
- OWASP Top 10 and CWE knowledge base (15 vulnerability patterns)
- Intelligent, autonomous operation with high accuracy

Example Usage:
    >>> from brainary.domains.java_security import JavaSecurityDetector, DetectionConfig
    >>> 
    >>> # Quick scan
    >>> detector = JavaSecurityDetector()
    >>> result = detector.quick_scan("path/to/java/project")
    >>> print(result["summary"])
    >>> 
    >>> # Thorough scan with validation and remediation
    >>> result = detector.thorough_scan("path/to/java/project", focus_areas=["injection"])
    >>> detector.export_report("security_report.txt")
"""

__version__ = '1.0.0'

# Note: detector and primitives require full Brainary installation
# For standalone use, import only knowledge and tools
try:
    from .detector import JavaSecurityDetector, DetectionConfig
    from .agents import (
        ScannerAgent,
        AnalyzerAgent,
        ValidatorAgent,
        ReporterAgent,
        SecurityFinding
    )
    from .primitives import (
        AnalyzeCodePrimitive,
        DetectVulnerabilityPrimitive,
        ThinkSecurityPrimitive,
        ValidateFindingPrimitive,
        RecommendFixPrimitive
    )
    _FULL_FEATURES = True
except ImportError:
    _FULL_FEATURES = False
    print("Warning: Full Brainary features not available. Install brainary for complete functionality.")


def register_security_primitives():
    """
    Register security domain primitives with Brainary's routing system.
    
    Call this before using JavaSecurityDetector to ensure all primitives
    are available to the kernel's routing and execution system.
    
    This registers primitives with both:
    1. The registry (for metadata and discovery)
    2. The router (for intelligent routing during kernel.execute())
    """
    if not _FULL_FEATURES:
        raise RuntimeError("Cannot register primitives: Brainary not fully installed")
    
    from brainary.primitive import (
        register_implementation, 
        get_global_registry,
        get_primitive_catalog,
        PrimitiveDef,
        PrimitiveLevel
    )
    from brainary.primitive.base import PrimitiveLevel
    
    registry = get_global_registry()
    catalog = get_primitive_catalog()
    
    # Step 1: Register primitive definitions in catalog
    # This defines WHAT operations exist (names and metadata)
    primitive_defs = [
        PrimitiveDef(
            name='think_security',
            level=PrimitiveLevel.DOMAIN,
            description='Security-focused reasoning about code vulnerabilities',
            input_schema={'context': 'ExecutionContext', 'code': 'str', 'focus': 'Optional[str]'},
            output_schema={'analysis': 'str', 'vulnerabilities': 'List[Dict]'},
            tags={'security', 'java', 'vulnerability', 'reasoning'}
        ),
        PrimitiveDef(
            name='analyze_code',
            level=PrimitiveLevel.DOMAIN,
            description='Analyze code for security issues',
            input_schema={'context': 'ExecutionContext', 'code': 'str', 'vulnerability_type': 'Optional[str]'},
            output_schema={'findings': 'List[Dict]', 'summary': 'str'},
            tags={'security', 'java', 'analysis', 'static_analysis'}
        ),
        PrimitiveDef(
            name='detect_vulnerability',
            level=PrimitiveLevel.DOMAIN,
            description='Detect vulnerabilities using pattern matching',
            input_schema={'context': 'ExecutionContext', 'code': 'str', 'pattern': 'Optional[str]'},
            output_schema={'vulnerabilities': 'List[Dict]'},
            tags={'security', 'java', 'detection', 'patterns'}
        ),
        PrimitiveDef(
            name='validate_finding',
            level=PrimitiveLevel.DOMAIN,
            description='Validate findings and eliminate false positives',
            input_schema={'context': 'ExecutionContext', 'finding': 'Dict', 'code_context': 'str'},
            output_schema={'valid': 'bool', 'confidence': 'str', 'reason': 'str'},
            tags={'security', 'java', 'validation', 'false_positive'}
        ),
        PrimitiveDef(
            name='recommend_fix',
            level=PrimitiveLevel.DOMAIN,
            description='Recommend fixes for security vulnerabilities',
            input_schema={'context': 'ExecutionContext', 'vulnerability': 'Dict', 'code': 'str'},
            output_schema={'recommendation': 'str', 'code_example': 'str'},
            tags={'security', 'java', 'remediation', 'fix'}
        ),
    ]
    
    for prim_def in primitive_defs:
        try:
            catalog.register(prim_def)
        except ValueError:
            # Already registered, skip
            pass
    
    # Step 2: Register implementations with router
    # This defines HOW to execute each primitive
    implementations = [
        ('think_security', ThinkSecurityPrimitive(), {
            'domain': 'security',
            'capabilities': ['security_analysis', 'vulnerability_reasoning'],
            'tags': ['java', 'security', 'vulnerability'],
        }),
        ('analyze_code', AnalyzeCodePrimitive(), {
            'domain': 'security',
            'capabilities': ['code_analysis', 'security_review'],
            'tags': ['java', 'security', 'static_analysis'],
        }),
        ('detect_vulnerability', DetectVulnerabilityPrimitive(), {
            'domain': 'security',
            'capabilities': ['vulnerability_detection', 'pattern_matching'],
            'tags': ['java', 'security', 'detection'],
        }),
        ('validate_finding', ValidateFindingPrimitive(), {
            'domain': 'security',
            'capabilities': ['validation', 'false_positive_elimination'],
            'tags': ['java', 'security', 'validation'],
        }),
        ('recommend_fix', RecommendFixPrimitive(), {
            'domain': 'security',
            'capabilities': ['remediation', 'fix_recommendation'],
            'tags': ['java', 'security', 'remediation'],
        }),
    ]
    
    for name, primitive, metadata in implementations:
        register_implementation(name, primitive, metadata)
        registry.register(primitive, metadata)
    
    print(f"Registered {len(primitive_defs)} security primitives with Brainary (catalog + router + registry)")


# These work standalone
from .knowledge import (
    VulnerabilityKnowledgeBase,
    VulnerabilityPattern,
    VulnerabilitySeverity,
    VulnerabilityCategory
)
from .tools import (
    CodeQLTool,
    PatternMatcher,
    SecurityScanner,
    ToolResult,
    ToolStatus
)

__all__ = [
    # Main API
    'JavaSecurityDetector',
    'DetectionConfig',
    'register_security_primitives',
    
    # Agents
    'ScannerAgent',
    'AnalyzerAgent',
    'ValidatorAgent',
    'ReporterAgent',
    'SecurityFinding',
    
    # Primitives
    'AnalyzeCodePrimitive',
    'DetectVulnerabilityPrimitive',
    'ThinkSecurityPrimitive',
    'ValidateFindingPrimitive',
    'RecommendFixPrimitive',
    
    # Knowledge
    'VulnerabilityKnowledgeBase',
    'VulnerabilityPattern',
    'VulnerabilitySeverity',
    'VulnerabilityCategory',
    
    # Tools
    'CodeQLTool',
    'PatternMatcher',
    'SecurityScanner',
    'ToolResult',
    'ToolStatus',
]
