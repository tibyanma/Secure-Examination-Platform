"""Transparent, provisional review-priority metrics; NOT cheating probabilities."""
from collections import Counter

WEIGHTS = {
    'multiple_faces': 25,
    'tab_switch': 15,
    'browser_action': 10,
    'face_absent': 10,
    'head_turned': 5,
    'other': 5,
}

def classify(reason):
    r = str(reason or '').lower()
    if 'more than one face' in r: return 'multiple_faces'
    if 'left the examination page' in r or 'outside the examination window' in r: return 'tab_switch'
    if 'no face was visible' in r: return 'face_absent'
    if 'head was turned away' in r: return 'head_turned'
    if any(x in r for x in ('copying', 'pasting', 'cutting', 'right-clicking', 'keyboard shortcut', 'browser shortcut', 'dragging')): return 'browser_action'
    return 'other'

def summarize(events):
    """events: dicts with event_type and reason; per exam attempt only."""
    warnings = [e for e in events if e['event_type'] == 'warning']
    counts = Counter(classify(e['reason']) for e in warnings)
    risk = min(100, sum(WEIGHTS[k] * n for k, n in counts.items()))
    terminated = any(e['event_type'] == 'terminated' for e in events)
    # Termination raises review priority, but does not assert misconduct.
    if terminated: risk = max(risk, 80)
    level = 'High' if risk >= 60 else 'Moderate' if risk >= 25 else 'Low'
    return {'risk': risk, 'trust': 100-risk, 'level': level,
            'warnings': len(warnings), 'terminated': terminated, 'counts': counts}

def split_attempts(events):
    """Split ordered event dictionaries at 'started'; older logs may lack boundaries."""
    attempts = []
    current = []
    for event in events:
        if event['event_type'] == 'started' and current:
            attempts.append(current)
            current = []
        current.append(event)
    if current: attempts.append(current)
    return attempts
    
def explain_risk(events):
    """
    Returns a transparent explanation of the risk score.
    Does not change the existing score calculation.
    """
    result = summarize(events)

    explanations = {
        "multiple_faces": "More than one face detected",
        "tab_switch": "Window or tab focus changed",
        "browser_action": "Restricted browser interaction",
        "face_absent": "Student face not detected",
        "head_turned": "Sustained head movement",
        "other": "Other monitoring warning",
    }

    factors = []

    for category, count in result["counts"].items():
        factors.append({
            "category": category,
            "description": explanations.get(category, category),
            "count": count,
            "weight": WEIGHTS.get(category, 0),
            "contribution": count * WEIGHTS.get(category, 0),
        })

    return {
        "risk": result["risk"],
        "trust": result["trust"],
        "level": result["level"],
        "factors": factors,
        "requires_human_review": (
            result["level"] != "Low" or result["terminated"]
        ),
        "interpretation": (
            "This is a provisional review-priority score, "
            "not a probability of cheating or proof of misconduct."
        )
    }    
