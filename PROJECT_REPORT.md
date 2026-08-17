# PROJECT REPORT
## Password Policy Testing & Credential Security Assessment Suite (CIPHERGUARD)

---

## 1. Executive Summary

Weak passwords remain one of the most critical attack vectors exploited in modern cybersecurity incidents. Attackers leverage automated dictionary engines, rule-based mutations, and GPU-accelerated brute-force searching to compromise user authentication systems.

The **CIPHERGUARD Password Security Assessment Suite** is a full-stack web application designed to evaluate password strength, audit compliance against **NIST SP 800-63B guidelines**, simulate Red Team dictionary mutation techniques, and analyze mathematical entropy. Built with a **Flask Python backend** and an **interactive dark/light mode dashboard UI**, the toolkit bridges offensive risk modeling with defensive mitigation strategies.

---

## 2. Project Motivation & Objectives

### Practical Motivation
User credentials serve as the primary access boundary for enterprise systems. Deficiencies in password policy enforcement lead to:
- **Account Takeovers & Credential Stuffing**
- **Privilege Escalation**
- **Data Breaches & Identity Theft**

### Core Objectives
1. **Red Team Attack Simulation**: Model rule-based dictionary generation, leet-speak transformations, and hardware hash cracking benchmarks.
2. **Mathematical Entropy Calculation**: Compute exact bits of entropy ($H = L \log_2 N$) with penalties for sequential keys and character repetition.
3. **NIST SP 800-63B Compliance Engine**: Verify candidate passwords against modern NIST guidelines (minimum length, common dictionary word rejections, repetition thresholds).
4. **Blue Team Enterprise Audit**: Audit bulk password samples to evaluate organizational security scores and visual risk tier distributions.
5. **Security Report Generation**: Export downloadable, executive-ready Markdown audit reports with risk metrics and mitigation steps.

---

## 3. System Architecture & Dual-Assessment Methodology

The system is structured around a **Dual-Team Cyber Assessment Model**:

```text
                                +-----------------------------------+
                                |     CIPHERGUARD SECURITY SUITE    |
                                +-----------------------------------+
                                                  |
                        +-------------------------+-------------------------+
                        |                                                   |
                        v                                                   v
           [RED TEAM OFFENSIVE MODULE]                         [BLUE TEAM DEFENSIVE MODULE]
    +---------------------------------------+           +---------------------------------------+
    | 1. Rule-based Dictionary Mutation     |           | 1. NIST SP 800-63B Policy Engine      |
    | 2. Leet-speak Normalization           |           | 2. Mathematical Entropy Calculator    |
    | 3. Hash Format & Cost Inspector       |           | 3. Enterprise Batch Health Metrics    |
    | 4. Hardware Crack Time Estimator      |           | 4. Executive Security Report Export   |
    +---------------------------------------+           +---------------------------------------+
```

---

## 4. Technical Implementation Details

### A. Mathematical Entropy Engine (`password_analyzer.py`)
Mathematical entropy measures the randomness and search space of a password:

$$\text{Entropy } (H) = L \times \log_2(N)$$

- $L$: Length of the password string.
- $N$: Size of character pool (lowercase=26, uppercase=26, digits=10, symbols=32; max $N = 94$).

The engine applies pattern penalties to reflect realistic dictionary vulnerabilities:
- **Repetition Penalty**: Deducts entropy proportionally when unique characters are low.
- **Keyboard Walk Penalty**: Deducts 5 bits per keyboard sequence (e.g. `qwerty`, `123456`).

### B. Theoretical Time-to-Crack Scenarios
Combinations search space is $2^H$. Average attempts required is $2^H / 2$. Crack time estimates are calculated across 5 attack vectors:
1. **Online Form (Rate-Limited)**: $10 \text{ req/sec}$
2. **Online API (Unthrottled)**: $1,000 \text{ req/sec}$
3. **Offline GPU Rig (Fast Hashes: MD5 / NTLM)**: $100,000,000,000 \text{ H/sec}$
4. **Offline GPU Rig (Standard Hashes: SHA-256)**: $10,000,000,000 \text{ H/sec}$
5. **Hardened KDF (Argon2id / Bcrypt)**: $50,000 \text{ H/sec}$

### C. Red Team Rule Mutations & Leet Normalization
The engine normalizes character substitutions to detect hidden dictionary words:
$$\text{@} \rightarrow \text{a}, \quad \text{3} \rightarrow \text{e}, \quad \text{1,!} \rightarrow \text{i}, \quad \text{0} \rightarrow \text{o}, \quad \text{\$,5} \rightarrow \text{s}$$

It models automated dictionary generation by applying combinations of suffix years (`2024`, `2025`, `2026`), case inversions, and special characters.

### D. Controlled Lab Hash Format Inspector
Identifies key derivation functions and algorithm specifications without invoking external tools:
- **Linux `/etc/shadow`**: `$6$` (SHA-512), `$5$` (SHA-256), `$1$` (MD5-Crypt), `$y$` (Yescrypt)
- **Windows SAM / Active Directory**: NTLM (32-hex string)
- **Hardened KDFs**: Bcrypt (`$2b$`), Argon2id (`$argon2`)

---

## 5. Web Interface & User Experience (`templates/index.html` & `static/`)

- **Live Dual Assessment Tab**: Displays live score gauge (0–100), entropy meter, crack time breakdown, and NIST compliance status.
- **Red Team Mutations Tab**: Provides wordlist generation tools, hash inspection controls, and hardware benchmark tables.
- **Blue Team Audit Tab**: Allows bulk password ingestion, calculating pass/fail compliance percentages and displaying Chart.js risk distribution graphs.
- **Report Generation Tab**: Renders a live preview of the Markdown report with one-click copy and download functionality (`security_password_audit_report.md`).
- **Dark & Light Mode Support**: Instant theme toggles with persistent `localStorage` saving.

---

## 6. Verification & Test Results

The suite includes an automated Python test suite (`test_analyzer.py`).

| Test Case | Objective | Result |
| :--- | :--- | :--- |
| `test_leetspeak_normalization` | Verifies `P@ssw0rd3` converts to `passwords` | **PASSED** |
| `test_entropy_calculation` | Asserts strong password entropy $> 60$ bits | **PASSED** |
| `test_nist_compliance_weak` | Confirms rejection of `123456` due to length/dict rules | **PASSED** |
| `test_nist_compliance_strong` | Confirms passphrase `correct-horse-battery-staple` compliance | **PASSED** |
| `test_hash_format_identification` | Validates recognition of `$6$` SHA-512 and NTLM strings | **PASSED** |

---

## 7. Project Deliverables Manifest

- **`password_analyzer.py`**: Defensive core analyzer & entropy engine.
- **`app.py`**: Flask REST server with endpoints (`/api/analyze`, `/api/audit-batch`, `/api/wordlist-rules`, `/api/inspect-hash`, `/api/export-report`).
- **`templates/index.html`**: Responsive cybersecurity dashboard HTML layout.
- **`static/css/style.css`**: CSS design tokens supporting Dark and Light themes.
- **`static/js/main.js`**: Frontend logic, API fetch handlers, Chart.js integrations, and theme persistence.
- **`test_analyzer.py`**: Automated unit test suite.
- **`requirements.txt`**: Python dependencies (`flask`, `jinja2`).

---

## 8. Conclusion & Learning Outcomes

This project demonstrates the practical application of cybersecurity concepts:
- **Red Team Knowledge**: Understanding how automated rule engines expand target wordlists and how hardware parameters dictate cracking speeds.
- **Blue Team Knowledge**: Applying NIST SP 800-63B recommendations, enforcing passphrase policies, and transitioning from legacy hashes (MD5/NTLM) to memory-hard key derivation functions (Argon2id).
- **Full-Stack Engineering**: Developing a clean, responsive web application for security evaluation.
