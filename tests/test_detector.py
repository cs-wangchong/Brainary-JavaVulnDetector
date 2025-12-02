"""
Tests for the main JavaSecurityDetector.
"""
import pytest
from java_security_detector.detector import JavaSecurityDetector


class TestJavaSecurityDetector:
    """Tests for JavaSecurityDetector."""
    
    def test_initialization(self):
        """Test detector initialization."""
        detector = JavaSecurityDetector()
        assert detector is not None
        assert hasattr(detector, 'scan_code')
        assert hasattr(detector, 'scan_file')
        assert hasattr(detector, 'scan_project')
    
    def test_scan_code_returns_report(self):
        """Test that scan_code returns a proper report structure."""
        detector = JavaSecurityDetector()
        
        test_code = '''
        public class TestClass {
            public void test(String input) {
                String query = "SELECT * FROM users WHERE id = " + input;
            }
        }
        '''
        
        report = detector.scan_code(test_code)
        assert isinstance(report, dict)
        assert 'vulnerabilities' in report or 'findings' in report or 'results' in report
    
    def test_scan_empty_code(self):
        """Test scanning empty code."""
        detector = JavaSecurityDetector()
        
        report = detector.scan_code('')
        assert isinstance(report, dict)
    
    def test_configuration_options(self):
        """Test that detector accepts configuration."""
        config = {
            'thorough': True,
            'patterns': ['sql_injection', 'xss']
        }
        
        detector = JavaSecurityDetector(config=config)
        assert detector is not None


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
