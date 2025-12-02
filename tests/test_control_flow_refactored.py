"""
Test refactored control flow using Brainary's built-in primitives.

Tests the enhanced conditional with LLM-based semantic evaluation.
"""

import sys
from pathlib import Path

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from brainary.core.kernel import CognitiveKernel
from brainary.core.context import ExecutionContext
from brainary.memory.working import WorkingMemory
from java_security_detector.control_flow import SecurityControlFlow


def test_simple_condition():
    """Test simple condition (should use direct evaluation)."""
    print("=" * 80)
    print("Test 1: Simple Condition")
    print("=" * 80)
    
    context = ExecutionContext(program_name="test_simple_condition")
    memory = WorkingMemory()
    kernel = CognitiveKernel()
    control_flow = SecurityControlFlow(context, memory, kernel)
    
    # Test simple "true" condition
    result = control_flow.conditional("true")
    print(f"Condition: 'true' -> Result: {result}")
    assert result == True, "Simple 'true' condition should return True"
    
    # Test simple "false" condition
    result = control_flow.conditional("false")
    print(f"Condition: 'false' -> Result: {result}")
    assert result == False, "Simple 'false' condition should return False"
    
    print("✅ Simple condition tests passed\n")


def test_semantic_condition():
    """Test semantic condition (should use LLM evaluation)."""
    print("=" * 80)
    print("Test 2: Semantic Condition with LLM")
    print("=" * 80)
    
    context = ExecutionContext(program_name="test_semantic_condition")
    memory = WorkingMemory()
    kernel = CognitiveKernel()
    control_flow = SecurityControlFlow(context, memory, kernel)
    
    # Test semantic condition about code
    code = """
    String userInput = request.getParameter("name");
    statement.execute("SELECT * FROM users WHERE name = '" + userInput + "'");
    """
    
    result = control_flow.conditional(
        "the code contains SQL injection vulnerability",
        code=code,
        description="Unsanitized user input directly concatenated into SQL query"
    )
    print(f"Condition: 'SQL injection vulnerability present'")
    print(f"Code snippet: {code[:50]}...")
    print(f"Result: {result}")
    print(f"Expected: True (dangerous SQL concatenation)")
    
    print("✅ Semantic condition test completed\n")


def test_security_helper_methods():
    """Test security-specific helper methods."""
    print("=" * 80)
    print("Test 3: Security Helper Methods")
    print("=" * 80)
    
    context = ExecutionContext(program_name="test_security_helpers")
    memory = WorkingMemory()
    kernel = CognitiveKernel()
    control_flow = SecurityControlFlow(context, memory, kernel)
    
    # Test is_input_validated
    validated_code = """
    String input = request.getParameter("name");
    if (input != null && input.matches("[a-zA-Z0-9]+")) {
        // Safe to use
        doSomething(input);
    }
    """
    
    unvalidated_code = """
    String input = request.getParameter("name");
    doSomething(input);  // Direct use without validation
    """
    
    print("Test: is_input_validated()")
    result1 = control_flow.is_input_validated(validated_code, "input")
    print(f"  Validated code -> {result1} (expected: True)")
    
    result2 = control_flow.is_input_validated(unvalidated_code, "input")
    print(f"  Unvalidated code -> {result2} (expected: False)")
    
    # Test has_security_controls
    print("\nTest: has_security_controls()")
    auth_code = """
    @PreAuthorize("hasRole('ADMIN')")
    public void deleteUser(String userId) {
        // Admin-only operation
    }
    """
    
    result3 = control_flow.has_security_controls(auth_code, "authorization")
    print(f"  Code with @PreAuthorize -> {result3} (expected: True)")
    
    print("✅ Security helper tests completed\n")


def test_should_analyze_deeply():
    """Test deep analysis decision logic."""
    print("=" * 80)
    print("Test 4: Deep Analysis Decision")
    print("=" * 80)
    
    context = ExecutionContext(program_name="test_deep_analysis_decisions")
    memory = WorkingMemory()
    kernel = CognitiveKernel()
    control_flow = SecurityControlFlow(context, memory, kernel)
    
    # Critical severity finding
    critical_finding = {
        "severity": "critical",
        "description": "SQL Injection vulnerability",
        "cwe_id": "CWE-89"
    }
    
    result1 = control_flow.should_analyze_deeply(critical_finding)
    print(f"Critical severity finding -> Deep analysis: {result1} (expected: True)")
    
    # Low severity finding
    low_finding = {
        "severity": "low",
        "description": "Missing comment in code",
        "cwe_id": ""
    }
    
    result2 = control_flow.should_analyze_deeply(low_finding)
    print(f"Low severity finding -> Deep analysis: {result2} (expected: False)")
    
    print("✅ Deep analysis decision tests completed\n")


def test_decision_summary():
    """Test decision tracking and summary."""
    print("=" * 80)
    print("Test 5: Decision Summary")
    print("=" * 80)
    
    context = ExecutionContext(program_name="test_decision_tracking")
    memory = WorkingMemory()
    kernel = CognitiveKernel()
    control_flow = SecurityControlFlow(context, memory, kernel)
    
    # Make several decisions
    control_flow.conditional("true", test="decision1")
    control_flow.conditional("false", test="decision2")
    control_flow.conditional("true", test="decision3")
    
    summary = control_flow.get_decision_summary()
    print(f"Total decisions: {summary['total_decisions']}")
    print(f"Conditions met: {summary['conditions_met']}")
    print(f"Conditions not met: {summary['conditions_not_met']}")
    print(f"Average confidence: {summary['average_confidence']:.2f}")
    
    print("\nRecent decisions:")
    for decision in summary['recent_decisions']:
        print(f"  - Condition: '{decision['condition']}' -> {decision['result']} "
              f"(confidence: {decision['confidence']:.2f})")
    
    print("✅ Decision summary test completed\n")


def main():
    """Run all tests."""
    print("\n" + "=" * 80)
    print("Testing Refactored SecurityControlFlow with Brainary Primitives")
    print("=" * 80)
    print()
    
    # Note: Primitives are now automatically registered when CognitiveKernel is initialized
    
    try:
        test_simple_condition()
        test_semantic_condition()
        test_security_helper_methods()
        test_should_analyze_deeply()
        test_decision_summary()
        
        print("=" * 80)
        print("✅ All tests completed successfully!")
        print("=" * 80)
        
        return 0
    
    except Exception as e:
        print(f"\n❌ Test failed with error: {e}")
        import traceback
        traceback.print_exc()
        return 1


if __name__ == "__main__":
    sys.exit(main())
