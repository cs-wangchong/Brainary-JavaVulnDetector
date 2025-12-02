#!/usr/bin/env python
"""
Run JavaSecurityDetector on test_project with detailed logging.

This script demonstrates the complete detection pipeline with comprehensive
logging at every phase.
"""

import sys
import os
from pathlib import Path
import logging
from datetime import datetime
import traceback

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

# Setup comprehensive logging
def setup_logging():
    """Configure detailed logging for detection process."""
    log_dir = Path(__file__).parent / "logs"
    log_dir.mkdir(exist_ok=True)
    
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    log_file = log_dir / f"detector_run_{timestamp}.log"
    
    # Create formatters
    detailed_formatter = logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - [%(filename)s:%(lineno)d] - %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    
    simple_formatter = logging.Formatter(
        '%(asctime)s - %(levelname)s - %(message)s',
        datefmt='%H:%M:%S'
    )
    
    # File handler - detailed logging
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)
    file_handler.setFormatter(detailed_formatter)
    
    # Console handler - less verbose
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_handler.setFormatter(simple_formatter)
    
    # Configure root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(logging.DEBUG)
    root_logger.addHandler(file_handler)
    root_logger.addHandler(console_handler)
    
    logger = logging.getLogger(__name__)
    logger.info("="*80)
    logger.info(f"Logging initialized. Log file: {log_file}")
    logger.info("="*80)
    
    return logger

logger = setup_logging()


def print_section(title: str):
    """Print formatted section header."""
    separator = "="*80
    print(f"\n{separator}")
    print(f"{title}")
    print(f"{separator}\n")
    logger.info(separator)
    logger.info(title)
    logger.info(separator)


def main():
    """Main execution function."""
    print_section("🔒 JavaSecurityDetector - Comprehensive Detection Run")
    
    logger.info("Starting JavaSecurityDetector execution")
    logger.info(f"Python version: {sys.version}")
    logger.info(f"Working directory: {os.getcwd()}")
    
    # Import detector
    print("📦 Loading JavaSecurityDetector...")
    logger.info("Importing java_security_detector module")
    
    try:
        from java_security_detector.detector import JavaSecurityDetector, DetectionConfig
        logger.info("✓ JavaSecurityDetector imported successfully")
        print("✅ Detector loaded successfully")
    except ImportError as e:
        logger.error(f"Failed to import JavaSecurityDetector: {e}", exc_info=True)
        print(f"❌ Failed to import detector: {e}")
        print("\nFull traceback:")
        traceback.print_exc()
        return 1
    except Exception as e:
        logger.error(f"Unexpected error importing detector: {e}", exc_info=True)
        print(f"❌ Unexpected error: {e}")
        traceback.print_exc()
        return 1
    
    # Locate test project - use the root java directory
    test_project = Path(__file__).parent / "test_project" / "src" / "main" / "java"
    logger.info(f"Test project path: {test_project}")
    logger.info(f"Test project exists: {test_project.exists()}")
    
    if not test_project.exists():
        logger.error(f"Test project not found at: {test_project}")
        print(f"❌ Test project not found: {test_project}")
        return 1
    
    # List Java files recursively
    java_files = list(test_project.rglob("*.java"))
    logger.info(f"Found {len(java_files)} Java files:")
    for jf in java_files:
        logger.info(f"  - {jf.relative_to(test_project)}")
    
    print(f"\n📁 Test Project: {test_project}/")
    print(f"   Files to analyze: {len(java_files)}")
    for jf in java_files:
        print(f"   - {jf.relative_to(test_project)}")
    
    # Initialize detector
    print_section("🚀 Initializing Detector")
    logger.info("Creating JavaSecurityDetector instance")
    
    try:
        # Create config for full detection
        config = DetectionConfig(
            deep_analysis=True,
            validate_findings=True,
            generate_remediation=True,
            max_findings=100,
            confidence_threshold="medium"
        )
        
        detector = JavaSecurityDetector()
        logger.info("✓ Detector initialized successfully")
        print("✅ Detector initialized")
        
        # Log detector configuration
        logger.info("Detector configuration:")
        logger.info(f"  - Deep analysis: {config.deep_analysis}")
        logger.info(f"  - Validate findings: {config.validate_findings}")
        logger.info(f"  - Generate remediation: {config.generate_remediation}")
        logger.info(f"  - Max findings: {config.max_findings}")
        logger.info(f"  - Confidence threshold: {config.confidence_threshold}")
        
    except Exception as e:
        logger.error(f"Failed to initialize detector: {e}", exc_info=True)
        print(f"❌ Initialization failed: {e}")
        print("\nFull traceback:")
        traceback.print_exc()
        return 1
    
    # Run detection
    print_section("🔍 Running Detection Pipeline")
    logger.info("="*80)
    logger.info("STARTING DETECTION PIPELINE")
    logger.info("="*80)
    
    print("""
Detection Pipeline:
  Phase 1: 🔎 Pattern-based scanning
  Phase 2: 🧠 LLM-powered deep analysis  
  Phase 3: ✓ Validation & false positive reduction
  Phase 4: 📊 Report generation
    """)
    
    logger.info("Calling detector.detect() with target: %s", str(test_project))
    
    try:
        # Run detection with detailed logging
        logger.info(">>> STARTING FULL DETECTION PIPELINE <<<")
        result = detector.detect(str(test_project), config=config)
        
        logger.info("Detection completed")
        logger.info(f"Result success: {result.get('success', False)}")
        logger.info(f"Findings count: {result.get('findings_count', 0)}")
        
    except Exception as e:
        logger.error("="*80)
        logger.error("DETECTION FAILED WITH EXCEPTION")
        logger.error("="*80)
        logger.error(f"Exception type: {type(e).__name__}")
        logger.error(f"Exception message: {str(e)}")
        logger.error("Full traceback:", exc_info=True)
        
        print(f"\n❌ Detection failed with error:")
        print(f"   {type(e).__name__}: {e}")
        print("\n📋 Full traceback:")
        traceback.print_exc()
        
        return 1
    
    # Process results
    print_section("📊 Detection Results")
    logger.info("="*80)
    logger.info("PROCESSING RESULTS")
    logger.info("="*80)
    
    if not result.get("success", False):
        logger.error("Detection reported failure")
        logger.error(f"Error: {result.get('error', 'Unknown error')}")
        print(f"❌ Detection failed: {result.get('error', 'Unknown error')}")
        return 1
    # Display statistics
    stats = result.get("statistics", {})
    findings_count = result.get("findings_count", 0)
    
    logger.info("Detection statistics:")
    logger.info(f"  Total findings: {findings_count}")
    logger.info(f"  Files scanned: {stats.get('files_scanned', 0)}")
    logger.info(f"  Processing time: {result.get('processing_time_ms', 0)}ms")
    
    # Count severity levels
    findings = result.get("findings", [])
    critical = sum(1 for f in findings if f.get('severity', '').lower() == 'critical')
    high = sum(1 for f in findings if f.get('severity', '').lower() == 'high')
    medium = sum(1 for f in findings if f.get('severity', '').lower() == 'medium')
    low = sum(1 for f in findings if f.get('severity', '').lower() == 'low')
    
    validated = sum(1 for f in findings if f.get('validated', False))
    with_remediation = sum(1 for f in findings if 'remediation' in f)
    
    print(f"""
✅ Detection Complete!

Statistics:
  📈 Total Findings: {findings_count}
  📁 Files Scanned: {stats.get('files_scanned', 0)}
  ⏱️  Processing Time: {result.get('processing_time_ms', 0)}ms
  
Severity Breakdown:
  🔴 Critical: {critical}
  🟠 High: {high}
  🟡 Medium: {medium}
  🟢 Low: {low}
  
Quality Metrics:
  ✓ Validated: {validated}
  🔧 With Remediation: {with_remediation}
    """)
    
    # Display findings
    findings = result.get("findings", [])
    logger.info(f"Processing {len(findings)} findings")
    
    if findings:
        print(f"� Detailed Findings ({len(findings)} total):\n")
        
        for i, finding in enumerate(findings, 1):
            severity = finding.get('severity', 'unknown').upper()
            vuln_type = finding.get('vulnerability_type', finding.get('type', 'Unknown'))
            file_path = finding.get('file_path', finding.get('file', 'Unknown'))
            line_num = finding.get('line_number', finding.get('line', 'N/A'))
            confidence = finding.get('confidence', 0.0)
            
            logger.info(f"Finding #{i}:")
            logger.info(f"  Type: {vuln_type}")
            logger.info(f"  Severity: {severity}")
            logger.info(f"  File: {file_path}")
            logger.info(f"  Line: {line_num}")
            logger.info(f"  Confidence: {confidence}")
            
            # Severity emoji
            severity_emoji = {
                'CRITICAL': '🔴',
                'HIGH': '🟠',
                'MEDIUM': '🟡',
                'LOW': '🟢'
            }.get(severity, '⚪')
            
            print(f"{severity_emoji} [{i}] {vuln_type}")
            print(f"    Severity: {severity}")
            
            # Show relative path if possible
            try:
                rel_path = Path(file_path).relative_to(test_project)
                print(f"    Location: {rel_path}:{line_num}")
            except:
                print(f"    Location: {Path(file_path).name}:{line_num}")
            
            print(f"    Confidence: {confidence:.2f}")
            
            # Show validation status
            if finding.get('validated'):
                print(f"    Status: ✓ Validated")
            
            # Show description
            description = finding.get('description', '')
            if description:
                desc_short = description[:150] + "..." if len(description) > 150 else description
                print(f"    Description: {desc_short}")
                logger.debug(f"  Full Description: {description}")
            
            # Show remediation if available
            if 'remediation' in finding:
                rem = finding['remediation']
                if isinstance(rem, dict):
                    print(f"    🔧 Remediation available")
                    if rem.get('fix_description'):
                        fix_desc = rem['fix_description'][:100] + "..." if len(rem['fix_description']) > 100 else rem['fix_description']
                        print(f"       {fix_desc}")
            
            print()
    else:
        logger.info("No findings to display")
        print("✅ No vulnerabilities found!")
    
    # Display summary
    summary = result.get("summary", "")
    if summary:
        print_section("📋 Executive Summary")
        logger.info("Executive summary:")
        logger.info(summary)
        print(summary)
    
    # Save reports
    print_section("💾 Saving Reports")
    
    # Create output directory
    output_dir = Path(__file__).parent / "detection_output"
    output_dir.mkdir(exist_ok=True)
    logger.info(f"Output directory: {output_dir}")
    
    # Save JSON report
    json_path = output_dir / "detection_report.json"
    logger.info(f"Saving JSON report to: {json_path}")
    
    try:
        detector.export_report(result, str(json_path), format="json")
        logger.info("✓ JSON report saved successfully")
        print(f"✅ JSON report saved: {json_path.relative_to(Path(__file__).parent)}")
    except Exception as e:
        logger.error(f"Failed to save JSON report: {e}", exc_info=True)
        print(f"❌ Failed to save JSON report: {e}")
    
    # Save Markdown report  
    md_path = output_dir / "detection_report.md"
    logger.info(f"Saving Markdown report to: {md_path}")
    
    try:
        detector.export_report(result, str(md_path), format="md")
        logger.info("✓ Markdown report saved successfully")
        print(f"✅ Markdown report saved: {md_path.relative_to(Path(__file__).parent)}")
    except Exception as e:
        logger.error(f"Failed to save Markdown report: {e}", exc_info=True)
        print(f"❌ Failed to save Markdown report: {e}")
    summary = result.get("summary", "")
    if summary:
        print_section("📋 Executive Summary")
        logger.info("Executive summary:")
        logger.info(summary)
        print(summary)
    
    print_section("✅ Detection Pipeline Complete")
    logger.info("="*80)
    logger.info("DETECTION PIPELINE COMPLETED SUCCESSFULLY")
    logger.info("="*80)
    
    return 0


if __name__ == "__main__":
    try:
        exit_code = main()
        sys.exit(exit_code)
    except KeyboardInterrupt:
        logger.warning("Execution interrupted by user")
        print("\n\n⚠️  Interrupted by user")
        sys.exit(130)
    except Exception as e:
        logger.critical(f"Unexpected error in main: {e}", exc_info=True)
        print(f"\n\n❌ Unexpected error: {e}")
        traceback.print_exc()
        sys.exit(1)
