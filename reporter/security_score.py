"""
Security Score Module - Calculates security scores based on findings
"""

def calculate_security_score(findings):
    """
    Calculate a security score based on findings
    
    Args:
        findings (list): List of findings
        
    Returns:
        dict: Security score information
    """
    # Count findings by risk level
    risk_counts = {
        'CRITICAL': 0,
        'HIGH': 0,
        'MEDIUM': 0,
        'LOW': 0
    }
    
    for finding in findings:
        risk = finding.get('Risk', 'UNKNOWN')
        if risk in risk_counts:
            risk_counts[risk] += 1
    
    # Calculate weighted score
    # Formula: 100 - (CRITICAL*10 + HIGH*5 + MEDIUM*2 + LOW*0.5) / total_possible * 100
    # This gives a score from 0-100 where 100 is perfect security
    
    total_findings = sum(risk_counts.values())
    if total_findings == 0:
        # No findings means perfect score
        raw_score = 100
    else:
        # Calculate weighted penalty
        weighted_penalty = (
            risk_counts['CRITICAL'] * 10 +
            risk_counts['HIGH'] * 5 +
            risk_counts['MEDIUM'] * 2 +
            risk_counts['LOW'] * 0.5
        )
        
        # Calculate maximum possible penalty (if all findings were CRITICAL)
        max_penalty = total_findings * 10
        
        # Calculate score (0-100)
        raw_score = 100 - (weighted_penalty / max_penalty * 100)
    
    # Ensure score is between 0 and 100
    score = max(0, min(100, round(raw_score)))
    
    # Determine label and CSS class based on score
    if score >= 90:
        label = "Excellent"
        css_class = "score-excellent"
        description = "Your AWS environment has very few security issues. Continue monitoring for new vulnerabilities."
    elif score >= 75:
        label = "Good"
        css_class = "score-good"
        description = "Your AWS environment is relatively secure but has some issues that should be addressed."
    elif score >= 60:
        label = "Fair"
        css_class = "score-fair"
        description = "Your AWS environment has several security issues that require attention."
    elif score >= 40:
        label = "Poor"
        css_class = "score-poor"
        description = "Your AWS environment has significant security vulnerabilities that need immediate attention."
    else:
        label = "Critical"
        css_class = "score-critical"
        description = "Your AWS environment has critical security issues that must be addressed immediately."
    
    return {
        'score': score,
        'label': label,
        'css_class': css_class,
        'description': description,
        'risk_counts': risk_counts
    }