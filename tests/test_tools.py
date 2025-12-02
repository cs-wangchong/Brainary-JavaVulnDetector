"""
Tests for security detection tools.
"""
import pytest
from java_security_detector.tools import PatternMatcher, SecurityScanner


class TestPatternMatcher:
    """Tests for PatternMatcher tool."""
    
    def test_initialization(self):
        """Test PatternMatcher initialization."""
        matcher = PatternMatcher()
        assert matcher.name == "PatternMatcher"
        assert hasattr(matcher, 'match')
    
    def test_sql_injection_detection(self):
        """Test SQL injection pattern detection."""
        matcher = PatternMatcher()
        
        # Vulnerable code
        vulnerable_code = '''
        String query = "SELECT * FROM users WHERE id = " + userId;
        Statement stmt = connection.createStatement();
        ResultSet rs = stmt.executeQuery(query);
        '''
        
        result = matcher.match(vulnerable_code, pattern_type='sql_injection')
        assert result['found'] is True
        assert len(result['matches']) > 0
    
    def test_safe_code_no_match(self):
        """Test that safe code doesn't trigger false positives."""
        matcher = PatternMatcher()
        
        # Safe code
        safe_code = '''
        PreparedStatement stmt = connection.prepareStatement("SELECT * FROM users WHERE id = ?");
        stmt.setString(1, userId);
        ResultSet rs = stmt.executeQuery();
        '''
        
        result = matcher.match(safe_code, pattern_type='sql_injection')
        # This should not match SQL injection pattern
        assert result['found'] is False or len(result['matches']) == 0


class TestSecurityScanner:
    """Tests for SecurityScanner tool."""
    
    def test_initialization(self):
        """Test SecurityScanner initialization."""
        scanner = SecurityScanner()
        assert scanner.name == "SecurityScanner"
        assert hasattr(scanner, 'scan_file')
        assert hasattr(scanner, 'scan_project')
    
    def test_scan_file_structure(self):
        """Test that scan_file returns proper structure."""
        scanner = SecurityScanner()
        
        test_code = '''
        public class Test {
            public void vulnerable(String input) {
                String query = "SELECT * FROM users WHERE name = '" + input + "'";
            }
        }
        '''
        
        result = scanner.scan_file(test_code, file_path='Test.java')
        assert isinstance(result, dict)
        assert 'file_path' in result
        assert 'vulnerabilities' in result
        assert isinstance(result['vulnerabilities'], list)
    
    def test_scan_project_structure(self):
        """Test that scan_project returns proper structure."""
        scanner = SecurityScanner()
        
        # Mock project data
        files = {
            'File1.java': 'public class File1 { }',
            'File2.java': 'public class File2 { }'
        }
        
        result = scanner.scan_project(files)
        assert isinstance(result, dict)
        assert 'total_files' in result
        assert 'total_vulnerabilities' in result
        assert 'files' in result
        assert result['total_files'] == len(files)


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
