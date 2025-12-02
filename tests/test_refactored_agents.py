"""
Test refactored agents that use kernel primitives directly.

This test verifies that agents work correctly after removing the SecurityControlFlow
wrapper and integrating control flow logic directly using kernel.execute().
"""

import pytest
from brainary.core.context import ExecutionContext
from brainary.core.kernel import CognitiveKernel

from java_security_detector.agents import AnalyzerAgent, ValidatorAgent


class TestRefactoredAnalyzerAgent:
    """Test AnalyzerAgent with direct kernel primitive integration"""
    
    def setup_method(self):
        """Setup test environment"""
        self.kernel = CognitiveKernel()
        self.context = ExecutionContext(program_name="test_analyzer")
        self.agent = AnalyzerAgent(kernel=self.kernel)
    
    def test_initialization(self):
        """Test agent initializes correctly without SecurityControlFlow"""
        assert self.agent.kernel is not None
        assert self.agent.memory is not None
        assert hasattr(self.agent, 'decisions')
        assert hasattr(self.agent, '_should_analyze_deeply')
        assert hasattr(self.agent, '_conditional') == False  # Only ValidatorAgent has this
    
    def test_should_analyze_deeply_critical_severity(self):
        """Test that critical severity findings are marked for deep analysis"""
        finding = {
            "severity": "critical",
            "description": "SQL injection vulnerability",
            "cwe_id": "CWE-89",
            "file": "test.java",
            "line": 42
        }
        
        result = self.agent._should_analyze_deeply(finding)
        
        # Critical severity should always trigger deep analysis
        assert result is True
        assert len(self.agent.decisions) > 0
        assert any(d["type"] == "severity_check" for d in self.agent.decisions)
    
    def test_should_analyze_deeply_low_severity(self):
        """Test that low severity findings may be skipped"""
        finding = {
            "severity": "low",
            "description": "Minor code quality issue",
            "cwe_id": "CWE-1234",
            "file": "test.java",
            "line": 42
        }
        
        result = self.agent._should_analyze_deeply(finding)
        
        # May or may not require deep analysis - just check it runs
        assert isinstance(result, bool)
        assert len(self.agent.decisions) > 0
    
    def test_should_analyze_deeply_dangerous_pattern(self):
        """Test that dangerous patterns trigger deep analysis"""
        finding = {
            "severity": "high",
            "description": "SQL injection detected in user input",
            "cwe_id": "CWE-89",
            "code_snippet": "query = \"SELECT * FROM users WHERE id = \" + userId;",
            "file": "test.java",
            "line": 42
        }
        
        result = self.agent._should_analyze_deeply(finding)
        
        # SQL injection is a dangerous pattern
        assert result is True
        assert len(self.agent.decisions) > 0
    
    def test_decision_tracking(self):
        """Test that decisions are tracked correctly"""
        self.agent.decisions.clear()
        
        finding = {
            "severity": "high",
            "description": "Test finding",
            "cwe_id": "CWE-89",
            "file": "test.java",
            "line": 42
        }
        
        self.agent._should_analyze_deeply(finding)
        
        assert len(self.agent.decisions) > 0
        decision = self.agent.decisions[0]
        assert "type" in decision
        assert "result" in decision
        assert "confidence" in decision
    
    def test_get_decision_summary(self):
        """Test decision summary generation"""
        self.agent.decisions = [
            {"type": "test1", "result": True, "confidence": 0.9},
            {"type": "test2", "result": False, "confidence": 0.8},
            {"type": "test3", "result": True, "confidence": 0.95}
        ]
        
        summary = self.agent._get_decision_summary()
        
        assert summary["total_decisions"] == 3
        assert summary["conditions_met"] == 2
        assert 0.8 < summary["average_confidence"] < 0.9
    
    def test_execute_with_findings(self):
        """Test execute method with sample findings"""
        findings = [
            {
                "severity": "high",
                "description": "SQL injection",
                "cwe_id": "CWE-89",
                "file": "test.java",
                "line": 42,
                "code_snippet": "query = \"SELECT * FROM users WHERE id = \" + userId;",
                "match": "query = \"SELECT * FROM users WHERE id = \" + userId;"
            }
        ]
        
        result = self.agent.execute(self.context, findings)
        
        assert result["success"] is True
        assert "analyzed_count" in result
        assert "skipped_count" in result
        assert "control_flow_stats" in result
        assert len(self.agent.decisions) > 0


class TestRefactoredValidatorAgent:
    """Test ValidatorAgent with direct kernel primitive integration"""
    
    def setup_method(self):
        """Setup test environment"""
        self.kernel = CognitiveKernel()
        self.context = ExecutionContext(program_name="test_validator")
        self.agent = ValidatorAgent(kernel=self.kernel)
    
    def test_initialization(self):
        """Test agent initializes correctly without SecurityControlFlow"""
        assert self.agent.kernel is not None
        assert self.agent.memory is not None
        assert hasattr(self.agent, 'decisions')
        assert hasattr(self.agent, '_should_skip_validation')
        assert hasattr(self.agent, '_conditional')
        assert hasattr(self.agent, '_assess_confidence')
        assert hasattr(self.agent, '_get_optimization_insights')
    
    def test_should_skip_validation_critical_severity(self):
        """Test that critical findings are never skipped"""
        finding = {
            "severity": "critical",
            "description": "Remote code execution",
            "cwe_id": "CWE-502"
        }
        
        result = self.agent._should_skip_validation(finding)
        
        # Critical severity should never be skipped
        assert result is False
    
    def test_should_skip_validation_with_false_positive_analysis(self):
        """Test that clear false positives may be skipped"""
        finding = {
            "severity": "medium",
            "description": "Potential issue",
            "cwe_id": "CWE-1234"
        }
        
        analysis = {
            "analysis": "This is clearly a false positive with no exploitable path. The input is validated.",
            "confidence": 0.95
        }
        
        result = self.agent._should_skip_validation(finding, analysis)
        
        # May or may not be skipped - just check it runs
        assert isinstance(result, bool)
    
    def test_conditional_evaluation(self):
        """Test conditional evaluation helper"""
        self.agent.context = self.context
        self.agent.decisions.clear()
        
        result = self.agent._conditional(
            "the severity is high or critical",
            severity="high"
        )
        
        assert isinstance(result, bool)
        assert len(self.agent.decisions) > 0
        assert any(d["type"] == "conditional" for d in self.agent.decisions)
    
    def test_assess_confidence(self):
        """Test confidence assessment using reflect primitive"""
        self.agent.context = self.context
        
        finding = {
            "severity": "high",
            "description": "SQL injection",
            "cwe_id": "CWE-89"
        }
        
        analysis = {
            "valid": True,
            "confidence": "high"
        }
        
        confidence = self.agent._assess_confidence(finding, analysis)
        
        assert isinstance(confidence, float)
        assert 0.0 <= confidence <= 1.0
    
    def test_get_optimization_insights(self):
        """Test optimization insights using monitor primitive"""
        self.agent.context = self.context
        self.agent.decisions = [
            {"type": "test", "result": True, "confidence": 0.9}
        ]
        
        insights = self.agent._get_optimization_insights()
        
        assert isinstance(insights, dict)
        assert "status" in insights
        assert "alerts" in insights
        assert "recommendations" in insights
    
    def test_decision_tracking(self):
        """Test that decisions are tracked correctly"""
        self.agent.decisions.clear()
        
        self.agent._record_decision("test_decision", True, 0.85)
        
        assert len(self.agent.decisions) == 1
        decision = self.agent.decisions[0]
        assert decision["type"] == "test_decision"
        assert decision["result"] is True
        assert decision["confidence"] == 0.85
    
    def test_get_decision_summary(self):
        """Test decision summary generation"""
        self.agent.decisions = [
            {"type": "test1", "result": True, "confidence": 0.9},
            {"type": "test2", "result": False, "confidence": 0.7},
            {"type": "test3", "result": True, "confidence": 0.8}
        ]
        
        summary = self.agent._get_decision_summary()
        
        assert summary["total_decisions"] == 3
        assert summary["conditions_met"] == 2
        assert abs(summary["average_confidence"] - 0.8) < 0.05


if __name__ == "__main__":
    pytest.main([__file__, "-v"])
