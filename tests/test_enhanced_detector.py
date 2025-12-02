"""
Test the enhanced security detector with intelligent control flow.

This demonstrates how conditional, reflect, and monitor primitives
are used for adaptive detection.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from java_security_detector.detector import JavaSecurityDetector
from java_security_detector.enhanced_primitives import register_enhanced_primitives


def main():
    """Test enhanced detector with control flow."""
    
    print("=" * 80)
    print("Enhanced Java Security Detector with Intelligent Control Flow")
    print("=" * 80)
    print()
    
    # Register enhanced primitives (overrides base primitives)
    print("🔧 Registering enhanced primitives with intelligent control flow...")
    register_enhanced_primitives()
    print("✅ Enhanced primitives registered\n")
    
    # Create detector
    detector = JavaSecurityDetector()
    
    # Test project path
    test_project = Path(__file__).parent / "test_project" / "vulnerable"
    
    if not test_project.exists():
        print(f"❌ Test project not found: {test_project}")
        return 1
    
    print(f"📂 Target: {test_project}")
    print(f"🔍 Detection mode: Deep analysis with intelligent control flow\n")
    
    # Run detection with enhanced control flow
    print("Starting detection with intelligent control flow...")
    print("-" * 80)
    
    results = detector.detect(
        str(test_project),
        deep_analysis=True,
        validate_findings=True,
        max_findings=20  # Test with more findings to see control flow in action
    )
    
    print("-" * 80)
    print()
    
    # Display results
    if results.get("success"):
        findings = results.get("validated_findings", [])
        false_positives = results.get("false_positives", [])
        
        print(f"✅ Detection completed successfully!")
        print()
        print("📊 Results Summary:")
        print(f"  Total findings: {len(findings) + len(false_positives)}")
        print(f"  Validated vulnerabilities: {len(findings)}")
        print(f"  False positives: {len(false_positives)}")
        print()
        
        # Show control flow statistics
        if "control_flow_stats" in results:
            stats = results["control_flow_stats"]
            print("🧠 Intelligent Control Flow Statistics:")
            print(f"  Total decisions made: {stats.get('total_decisions', 0)}")
            print(f"  Conditions met: {stats.get('conditions_met', 0)}")
            print(f"  Conditions not met: {stats.get('conditions_not_met', 0)}")
            print(f"  Average confidence: {stats.get('average_confidence', 0):.2f}")
            print()
            
            # Show recent decisions
            recent = stats.get('recent_decisions', [])
            if recent:
                print("  Recent control flow decisions:")
                for i, decision in enumerate(recent[-5:], 1):
                    print(f"    {i}. {decision['condition']}")
                    print(f"       → Result: {decision['result']}, Confidence: {decision['confidence']:.2f}, Branch: {decision['branch']}")
                print()
        
        # Show optimization insights
        if "optimization_insights" in results:
            insights = results["optimization_insights"]
            print("💡 Strategy Optimization Insights:")
            for insight in insights.get('insights', [])[:3]:
                print(f"  • {insight}")
            print()
            recommendations = insights.get('recommendations', [])
            if recommendations:
                print("📋 Recommendations:")
                for rec in recommendations[:3]:
                    print(f"  • {rec}")
                print()
        
        # Display validated findings
        if findings:
            print("🔴 Validated Vulnerabilities:")
            print()
            for i, finding in enumerate(findings[:5], 1):
                cwe_id = finding.get("cwe_id", "Unknown")
                file_path = finding.get("file", "Unknown")
                line = finding.get("line", "?")
                confidence = finding.get("confidence", "unknown")
                conf_score = finding.get("confidence_score", 0.0)
                
                print(f"  {i}. {cwe_id} in {Path(file_path).name}:{line}")
                print(f"     Confidence: {confidence} (score: {conf_score:.2f})")
                print(f"     Validated: {finding.get('validated', False)}")
                
                # Show validation notes if available
                notes = finding.get("validation_notes", "")
                if notes and len(notes) < 100:
                    print(f"     Notes: {notes[:100]}")
                print()
            
            if len(findings) > 5:
                print(f"  ... and {len(findings) - 5} more vulnerabilities")
                print()
        
        # Show skipped findings stats
        if "skipped_count" in results:
            print(f"⏭️  Skipped {results['skipped_count']} low-priority findings (intelligent triage)")
        
        if "skipped_validation_count" in results:
            print(f"⚡ Skipped validation for {results['skipped_validation_count']} findings (pattern-based detection)")
        
        print()
        print("=" * 80)
        print("Key Features Demonstrated:")
        print("  ✓ Intelligent conditional logic for analysis prioritization")
        print("  ✓ Reflection on validation accuracy")
        print("  ✓ Monitoring of detection quality")
        print("  ✓ Adaptive strategy based on feedback")
        print("  ✓ Fine-grained control flow decisions")
        print("=" * 80)
        
        return 0
    else:
        error = results.get("error", "Unknown error")
        print(f"❌ Detection failed: {error}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
