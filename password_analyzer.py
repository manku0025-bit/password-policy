import math
import re
import string

# Common weak passwords and dictionary list for defensive checking
COMMON_WEAK_PASSWORDS = {
    "123456", "password", "123456789", "12345678", "12345", "1234567", "1234",
    "qwerty", "dragon", "pussy", "baseball", "football", "letmein", "monkey",
    "shadow", "mustang", "master", "michael", "superman", "654321", "jordan",
    "access", "secret", "welcome", "admin", "admin123", "password123", "pass123",
    "iloveyou", "trustno1", "princess", "solo", "cheers", "starwars", "harley"
}

# Common keyboard walking patterns
KEYBOARD_PATTERNS = [
    "qwertyuiop", "asdfghjkl", "zxcvbnm",
    "1234567890", "0987654321", "poiuytrewq", "lkjhgfdsa", "mnbvcxz"
]

# Leet-speak normalization lookup
LEET_MAP = {
    '@': 'a', '4': 'a',
    '8': 'b',
    '(': 'c', '<': 'c',
    '3': 'e',
    '1': 'i', '!': 'i', '|': 'i',
    '0': 'o',
    '$': 's', '5': 's',
    '7': 't', '+': 't',
    'v': 'u', '^': 'u',
    'z': '2'
}

def normalize_leetspeak(text):
    """Converts leet-speak characters to standard lowercase Latin characters."""
    normalized = []
    for char in text.lower():
        normalized.append(LEET_MAP.get(char, char))
    return "".join(normalized)

def calculate_entropy(password):
    """
    Calculates mathematical entropy (bits) based on character pool size and length.
    H = L * log2(N)
    Also applies penalties for repetitive or sequential patterns.
    """
    if not password:
        return 0.0, 0, "Empty"

    length = len(password)
    has_lower = any(c in string.ascii_lowercase for c in password)
    has_upper = any(c in string.ascii_uppercase for c in password)
    has_digit = any(c in string.digits for c in password)
    has_symbol = any(c in string.punctuation or not c.isalnum() for c in password)

    pool_size = 0
    if has_lower:
        pool_size += 26
    if has_upper:
        pool_size += 26
    if has_digit:
        pool_size += 10
    if has_symbol:
        pool_size += 32

    if pool_size == 0:
        pool_size = 1

    # Base entropy calculation
    raw_entropy = length * math.log2(pool_size)

    # Pattern penalties
    penalty = 0.0
    
    # Repetition penalty
    unique_chars = len(set(password))
    if unique_chars < length:
        repeat_ratio = 1.0 - (unique_chars / length)
        penalty += raw_entropy * (repeat_ratio * 0.4)

    # Keyboard pattern penalty
    lower_pwd = password.lower()
    for pattern in KEYBOARD_PATTERNS:
        for i in range(len(pattern) - 2):
            sub = pattern[i:i+3]
            if sub in lower_pwd:
                penalty += 5.0

    adjusted_entropy = max(0.0, raw_entropy - penalty)
    return round(adjusted_entropy, 2), pool_size, "Calculated"

def format_time(seconds):
    """Formats raw seconds into human-readable duration strings."""
    if seconds < 0.001:
        return "Instant (< 1 millisecond)"
    elif seconds < 1:
        return f"{round(seconds * 1000, 2)} milliseconds"
    elif seconds < 60:
        return f"{round(seconds, 1)} seconds"
    elif seconds < 3600:
        return f"{round(seconds / 60, 1)} minutes"
    elif seconds < 86400:
        return f"{round(seconds / 3600, 1)} hours"
    elif seconds < 31536000:
        return f"{round(seconds / 86400, 1)} days"
    elif seconds < 3153600000:
        return f"{round(seconds / 31536000, 1)} years"
    elif seconds < 3153600000000:
        return f"{round(seconds / 31536000000, 1)} centuries"
    else:
        return "Trillions of years (Computationally Intractable)"

def estimate_crack_times(entropy):
    """
    Estimates theoretical time-to-crack based on different cracking attack scenarios.
    Combinations = 2 ^ Entropy
    """
    combinations = 2 ** entropy

    # Attack rates (hashes/evaluations per second)
    rates = {
        "online_throttled": 10,                 # Web form with rate limiting (10 req/s)
        "online_unthrottled": 1000,             # Unthrottled API endpoint (1,000 req/s)
        "offline_fast_hash": 100_000_000_000,   # GPU Cluster running MD5 / NTLM (100 Billion H/s)
        "offline_standard_hash": 10_000_000_000,# Standard GPU running SHA-256 (10 Billion H/s)
        "offline_hardened_hash": 50_000         # Key derivation bcrypt / Argon2 (50,000 H/s)
    }

    # Average combinations to check is combinations / 2
    avg_combinations = combinations / 2.0

    return {
        "combinations_count": f"{combinations:.2e}" if combinations > 1e9 else f"{int(combinations):,}",
        "scenarios": {
            "online_throttled": {
                "label": "Online Form (Rate-Limited, 10 req/sec)",
                "time": format_time(avg_combinations / rates["online_throttled"])
            },
            "online_unthrottled": {
                "label": "Online API (Unthrottled, 1,000 req/sec)",
                "time": format_time(avg_combinations / rates["online_unthrottled"])
            },
            "offline_fast": {
                "label": "Offline GPU Rig (Fast MD5/NTLM - 100B H/s)",
                "time": format_time(avg_combinations / rates["offline_fast_hash"])
            },
            "offline_standard": {
                "label": "Offline GPU Rig (SHA-256 - 10B H/s)",
                "time": format_time(avg_combinations / rates["offline_standard_hash"])
            },
            "offline_hardened": {
                "label": "Offline Hardened KDF (Argon2 / bcrypt - 50k H/s)",
                "time": format_time(avg_combinations / rates["offline_hardened_hash"])
            }
        }
    }

def check_nist_compliance(password):
    """
    Checks password against NIST SP 800-63B guidelines:
    - Minimum length 8 characters (15+ recommended for enterprise)
    - Rejects trivial repetition
    - Rejects common dictionary words and leet-speak variants
    - Rejects sequential patterns
    """
    issues = []
    passed_rules = []

    # 1. Length check
    if len(password) < 8:
        issues.append("Fails minimum length requirement (NIST requires at least 8 characters).")
    elif len(password) < 15:
        passed_rules.append("Meets basic NIST length (8+ chars), but 15+ chars is recommended for strong defense.")
    else:
        passed_rules.append("Exceeds recommended NIST length requirement (15+ characters).")

    # 2. Known weak password check
    norm_pwd = normalize_leetspeak(password)
    clean_alpha = re.sub(r'[^a-z]', '', norm_pwd)
    
    if password.lower() in COMMON_WEAK_PASSWORDS or norm_pwd in COMMON_WEAK_PASSWORDS or clean_alpha in COMMON_WEAK_PASSWORDS:
        issues.append("Contains a known weak dictionary password or obvious leet-speak variant.")
    else:
        passed_rules.append("No known common weak dictionary words detected.")

    # 3. Repetitive characters
    if re.search(r'(.)\1{3,}', password):
        issues.append("Contains 4 or more repetitive sequential characters (e.g. 'aaaa' or '1111').")
    else:
        passed_rules.append("Free of excessive character repetition.")

    # 4. Sequential patterns
    if re.search(r'(0123|1234|2345|3456|4567|5678|6789|abcd|bcde|cdef|defg)', password.lower()):
        issues.append("Contains simple sequential numbers or alphabetical series (e.g., '1234' or 'abcd').")
    else:
        passed_rules.append("Free of simple sequential patterns.")

    # 5. Keyboard paths
    has_walk = False
    for pat in KEYBOARD_PATTERNS:
        for i in range(len(pat) - 3):
            if pat[i:i+4] in password.lower():
                has_walk = True
                break
    if has_walk:
        issues.append("Contains sequential keyboard walking pattern (e.g., 'qwerty' or 'asdfgh').")
    else:
        passed_rules.append("No simple keyboard sequence patterns found.")

    is_compliant = len(issues) == 0
    return {
        "is_compliant": is_compliant,
        "issues": issues,
        "passed_rules": passed_rules
    }

def detect_weaknesses(password):
    """Detects structural and behavioral weaknesses in candidate passwords."""
    weaknesses = []
    
    if len(password) < 10:
        weaknesses.append({"type": "Short Length", "desc": "Short passwords are vulnerable to high-speed GPU offline brute-force search."})
    
    if password.isalpha():
        weaknesses.append({"type": "Alpha Only", "desc": "Lacks numbers or special symbols, significantly shrinking character search space."})

    if password.isdigit():
        weaknesses.append({"type": "Numeric Only", "desc": "PIN/Numeric-only string has a very small search space (10^N)."})

    norm = normalize_leetspeak(password)
    if norm != password.lower():
        weaknesses.append({"type": "Leet-Speak Substitution", "desc": "Substitutions like @ for 'a' or 3 for 'e' are automatically parsed by modern rule engines."})

    if re.search(r'(19|20)\d\d', password):
        weaknesses.append({"type": "Contains Year Pattern", "desc": "Appended years (e.g. 2024, 1998) are targeted first in hybrid dictionary attacks."})

    return weaknesses

def analyze_password(password):
    """
    Main evaluation pipeline for a candidate password.
    Returns comprehensive metrics, entropy, NIST status, crack duration estimates, and score.
    """
    if not password:
        return {
            "error": "Password cannot be empty.",
            "score": 0,
            "tier": "Invalid"
        }

    entropy, pool_size, method = calculate_entropy(password)
    crack_estimates = estimate_crack_times(entropy)
    nist_status = check_nist_compliance(password)
    weaknesses = detect_weaknesses(password)

    # Score calculation (0 to 100)
    # Entropy contribution (up to 70 pts), NIST compliance (up to 30 pts)
    entropy_score = min(70, (entropy / 80.0) * 70)
    nist_score = 30 if nist_status["is_compliant"] else max(0, 30 - (len(nist_status["issues"]) * 10))
    
    total_score = round(entropy_score + nist_score)
    total_score = max(0, min(100, total_score))

    # Tier assignment
    if total_score < 30:
        tier = "Critical Vulnerability (Very Weak)"
        badge_color = "danger"
    elif total_score < 55:
        tier = "Weak / Sub-standard"
        badge_color = "warning"
    elif total_score < 75:
        tier = "Moderate Security"
        badge_color = "info"
    elif total_score < 90:
        tier = "Strong Defense"
        badge_color = "success"
    else:
        tier = "Hardened Enterprise Grade"
        badge_color = "emerald"

    # Defensive recommendations
    recommendations = []
    if len(password) < 15:
        recommendations.append("Increase length to 15+ characters or adopt a multi-word passphrase (e.g. 'correct-horse-battery-staple').")
    if not nist_status["is_compliant"]:
        recommendations.append("Eliminate dictionary words, year numbers, and repetitive/sequential key patterns.")
    if pool_size < 62:
        recommendations.append("Combine uppercase, lowercase, numbers, and symbols to maximize character space entropy.")
    recommendations.append("Ensure your organization implements key-derivation hashing (Argon2id or bcrypt with high work factors) and MFA.")

    return {
        "password_length": len(password),
        "entropy": entropy,
        "pool_size": pool_size,
        "score": total_score,
        "tier": tier,
        "badge_color": badge_color,
        "nist_status": nist_status,
        "weaknesses": weaknesses,
        "crack_estimates": crack_estimates,
        "recommendations": recommendations
    }

def audit_batch(password_list):
    """Audits a list of passwords defensively to generate enterprise summary statistics."""
    total = len(password_list)
    if total == 0:
        return {"error": "No passwords provided for audit."}

    results = []
    compliant_count = 0
    total_entropy = 0
    tier_distribution = {"Critical": 0, "Weak": 0, "Moderate": 0, "Strong": 0, "Hardened": 0}

    for pwd in password_list:
        clean_pwd = pwd.strip()
        if not clean_pwd:
            continue
        res = analyze_password(clean_pwd)
        results.append({"password_sample": clean_pwd[:3] + "*" * (len(clean_pwd) - 3) if len(clean_pwd) > 3 else "***", "analysis": res})
        
        if res["nist_status"]["is_compliant"]:
            compliant_count += 1
        total_entropy += res["entropy"]

        score = res["score"]
        if score < 30:
            tier_distribution["Critical"] += 1
        elif score < 55:
            tier_distribution["Weak"] += 1
        elif score < 75:
            tier_distribution["Moderate"] += 1
        elif score < 90:
            tier_distribution["Strong"] += 1
        else:
            tier_distribution["Hardened"] += 1

    avg_entropy = round(total_entropy / total, 2)
    compliance_rate = round((compliant_count / total) * 100, 1)

    return {
        "total_audited": total,
        "compliance_rate": compliance_rate,
        "avg_entropy": avg_entropy,
        "tier_distribution": tier_distribution,
        "sample_results": results[:50] # return top 50 audited samples
    }

def identify_hash_format(hash_str):
    """Identifies hashing algorithm, cost spec, and difficulty tier defensively."""
    h = hash_str.strip()
    if not h:
        return {"algorithm": "Unknown", "cost": "N/A", "difficulty": "Low"}

    if h.startswith("$6$"):
        return {"algorithm": "SHA-512 (Linux /etc/shadow)", "cost": "5,000 Rounds", "difficulty": "High (Stretched Key)"}
    elif h.startswith("$5$"):
        return {"algorithm": "SHA-256 (Linux /etc/shadow)", "cost": "5,000 Rounds", "difficulty": "Moderate-High"}
    elif h.startswith("$1$"):
        return {"algorithm": "MD5-Crypt (Legacy Unix)", "cost": "1,000 Rounds", "difficulty": "Low-Moderate"}
    elif h.startswith("$y$"):
        return {"algorithm": "Yescrypt (Modern Linux)", "cost": "Memory-Hard KDF", "difficulty": "Hardened"}
    elif h.startswith("$2b$") or h.startswith("$2a$"):
        return {"algorithm": "Bcrypt Key Derivation", "cost": "2^10 Cost Factor", "difficulty": "Hardened Enterprise"}
    elif h.startswith("$argon2"):
        return {"algorithm": "Argon2id (Winner Password Hashing)", "cost": "Memory-Hard KDF", "difficulty": "Hardened Enterprise"}
    elif len(h) == 32 and all(c in "0123456789abcdefABCDEF" for c in h):
        return {"algorithm": "NTLM / Raw MD5 Hash", "cost": "1 Iteration (Unstretched)", "difficulty": "Low (GPU Fast Search)"}
    elif len(h) == 40 and all(c in "0123456789abcdefABCDEF" for c in h):
        return {"algorithm": "SHA-1 Raw Hash", "cost": "1 Iteration", "difficulty": "Low (GPU Fast Search)"}
    elif len(h) == 64 and all(c in "0123456789abcdefABCDEF" for c in h):
        return {"algorithm": "SHA-256 Raw Hash", "cost": "1 Iteration", "difficulty": "Moderate"}
    else:
        return {"algorithm": "Custom / Unknown Hash Format", "cost": "Unspecified", "difficulty": "Variable"}

