"""
Tests for the security knowledge base.
"""
import pytest
from java_security_detector.knowledge import VULNERABILITY_PATTERNS, get_pattern, list_patterns


def test_vulnerability_patterns_exist():
    """Test that vulnerability patterns are loaded."""
    assert len(VULNERABILITY_PATTERNS) > 0
    assert all(isinstance(p, dict) for p in VULNERABILITY_PATTERNS)


def test_pattern_structure():
    """Test that each pattern has required fields."""
    required_fields = {'id', 'name', 'category', 'severity', 'description', 'detection_rules'}
    
    for pattern in VULNERABILITY_PATTERNS:
        assert required_fields.issubset(pattern.keys()), f"Pattern missing fields: {pattern.get('id', 'unknown')}"
        assert pattern['severity'] in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']
        assert isinstance(pattern['detection_rules'], list)
        assert len(pattern['detection_rules']) > 0


def test_get_pattern():
    """Test retrieving specific pattern by ID."""
    # Get first pattern
    first_pattern = VULNERABILITY_PATTERNS[0]
    pattern_id = first_pattern['id']
    
    # Retrieve it
    retrieved = get_pattern(pattern_id)
    assert retrieved is not None
    assert retrieved['id'] == pattern_id
    
    # Test non-existent pattern
    assert get_pattern('nonexistent_pattern') is None


def test_list_patterns():
    """Test listing patterns by category and severity."""
    # All patterns
    all_patterns = list_patterns()
    assert len(all_patterns) == len(VULNERABILITY_PATTERNS)
    
    # Filter by category
    injection_patterns = list_patterns(category='Injection')
    assert all(p['category'] == 'Injection' for p in injection_patterns)
    
    # Filter by severity
    critical_patterns = list_patterns(severity='CRITICAL')
    assert all(p['severity'] == 'CRITICAL' for p in critical_patterns)
    
    # Combined filters
    critical_injection = list_patterns(category='Injection', severity='CRITICAL')
    assert all(p['category'] == 'Injection' and p['severity'] == 'CRITICAL' 
              for p in critical_injection)


def test_pattern_ids_unique():
    """Test that all pattern IDs are unique."""
    ids = [p['id'] for p in VULNERABILITY_PATTERNS]
    assert len(ids) == len(set(ids)), "Duplicate pattern IDs found"


def test_detection_rules_structure():
    """Test that detection rules have proper structure."""
    for pattern in VULNERABILITY_PATTERNS:
        for rule in pattern['detection_rules']:
            assert 'type' in rule
            assert rule['type'] in ['pattern', 'ast', 'codeql', 'semantic', 'dataflow']
            
            if rule['type'] == 'pattern':
                assert 'patterns' in rule
                assert isinstance(rule['patterns'], list)
            elif rule['type'] == 'codeql':
                assert 'query' in rule


if __name__ == '__main__':
    pytest.main([__file__, '-v'])
