"""
Command-line interface for Java Security Detector
"""

import argparse
import sys
from pathlib import Path

from .detector import JavaSecurityDetector, DetectionConfig
from .knowledge import VulnerabilityKnowledgeBase


def main():
    """Main CLI entry point"""
    parser = argparse.ArgumentParser(
        description="Intelligent Java vulnerability detection powered by Brainary",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Quick scan
  java-security-scan /path/to/java/project
  
  # Thorough scan with validation
  java-security-scan /path/to/project --thorough
  
  # Focus on specific vulnerabilities
  java-security-scan /path/to/project --focus injection xss
  
  # Export report
  java-security-scan /path/to/project --output report.txt --format txt
  
  # List vulnerability patterns
  java-security-scan --list-patterns
"""
    )
    
    parser.add_argument(
        "target",
        nargs="?",
        help="Target Java file or directory to scan"
    )
    
    parser.add_argument(
        "--thorough",
        action="store_true",
        help="Run thorough scan with deep analysis and validation"
    )
    
    parser.add_argument(
        "--quick",
        action="store_true",
        help="Run quick scan (pattern-based only)"
    )
    
    parser.add_argument(
        "--focus",
        nargs="+",
        metavar="AREA",
        help="Focus areas (e.g., injection, xss, crypto)"
    )
    
    parser.add_argument(
        "--max-findings",
        type=int,
        default=50,
        metavar="N",
        help="Maximum number of findings to process (default: 50)"
    )
    
    parser.add_argument(
        "--confidence",
        choices=["low", "medium", "high"],
        default="medium",
        help="Minimum confidence threshold (default: medium)"
    )
    
    parser.add_argument(
        "-o", "--output",
        metavar="FILE",
        help="Output report to file"
    )
    
    parser.add_argument(
        "--format",
        choices=["txt", "json", "html"],
        default="txt",
        help="Output format (default: txt)"
    )
    
    parser.add_argument(
        "--list-patterns",
        action="store_true",
        help="List all vulnerability patterns and exit"
    )
    
    parser.add_argument(
        "--pattern-info",
        metavar="CWE-ID",
        help="Show information about a specific vulnerability pattern"
    )
    
    parser.add_argument(
        "--no-validation",
        action="store_true",
        help="Skip LLM validation (faster but may have false positives)"
    )
    
    parser.add_argument(
        "--no-remediation",
        action="store_true",
        help="Skip remediation recommendations"
    )
    
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Verbose output"
    )
    
    args = parser.parse_args()
    
    # Handle list patterns
    if args.list_patterns:
        kb = VulnerabilityKnowledgeBase()
        print(kb.get_all_patterns_summary())
        return 0
    
    # Handle pattern info
    if args.pattern_info:
        kb = VulnerabilityKnowledgeBase()
        print(kb.get_detection_guidance(args.pattern_info))
        return 0
    
    # Validate target
    if not args.target:
        parser.error("target is required unless using --list-patterns or --pattern-info")
    
    target = Path(args.target)
    if not target.exists():
        print(f"Error: Target not found: {args.target}", file=sys.stderr)
        return 1
    
    # Create detector
    detector = JavaSecurityDetector()
    
    try:
        # Configure detection
        if args.quick:
            if args.verbose:
                print("Running quick scan...")
            result = detector.quick_scan(str(target))
        elif args.thorough:
            if args.verbose:
                print("Running thorough scan...")
            result = detector.thorough_scan(
                str(target),
                focus_areas=args.focus
            )
        else:
            # Custom configuration
            config = DetectionConfig(
                deep_analysis=True,
                validate_findings=not args.no_validation,
                generate_remediation=not args.no_remediation,
                max_findings=args.max_findings,
                focus_areas=args.focus,
                confidence_threshold=args.confidence
            )
            
            if args.verbose:
                print(f"Running scan with custom config...")
                print(f"  Deep analysis: {config.deep_analysis}")
                print(f"  Validate findings: {config.validate_findings}")
                print(f"  Generate remediation: {config.generate_remediation}")
            
            result = detector.detect(str(target), config)
        
        # Check success
        if not result["success"]:
            print(f"Error: Detection failed", file=sys.stderr)
            return 1
        
        # Print summary to stdout
        print("\n" + "=" * 80)
        print("SCAN COMPLETE")
        print("=" * 80)
        print(result["summary"])
        print("\nStatistics:")
        for key, value in result["statistics"].items():
            print(f"  {key}: {value}")
        
        # Export report if requested
        if args.output:
            if detector.export_report(args.output, format=args.format):
                print(f"\n✓ Report exported to: {args.output}")
            else:
                print(f"\n✗ Failed to export report", file=sys.stderr)
                return 1
        else:
            # Print report to stdout if not exported
            print("\n" + "=" * 80)
            print("DETAILED REPORT")
            print("=" * 80)
            print(result["report"])
        
        # Return exit code based on findings
        stats = result["statistics"]
        if stats.get("validated_findings", 0) > 0:
            # Count critical findings
            critical_count = len([
                f for f in result["findings"]
                if f.get("severity") == "critical"
            ])
            if critical_count > 0:
                print(f"\n⚠️  Found {critical_count} critical vulnerabilities!", file=sys.stderr)
                return 1
        
        return 0
    
    except KeyboardInterrupt:
        print("\n\nScan interrupted by user", file=sys.stderr)
        return 130
    except Exception as e:
        print(f"\nError: {e}", file=sys.stderr)
        if args.verbose:
            import traceback
            traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
