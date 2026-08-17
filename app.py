import io
import json
from flask import Flask, render_template, request, jsonify, make_response
from password_analyzer import analyze_password, audit_batch, normalize_leetspeak, identify_hash_format

app = Flask(__name__)

@app.route("/")
def index():
    """Render the main cybersecurity audit dashboard."""
    return render_template("index.html")

@app.route("/api/inspect-hash", methods=["POST"])
def api_inspect_hash():
    """Inspects raw hash string to identify algorithm type, iteration cost, and crack difficulty."""
    data = request.get_json() or {}
    hash_str = data.get("hash", "")
    if not hash_str:
        return jsonify({"error": "Hash string required."}), 400
    res = identify_hash_format(hash_str)
    return jsonify(res)

@app.route("/api/analyze", methods=["POST"])
def api_analyze():
    """Analyze a single candidate password."""
    data = request.get_json() or {}
    password = data.get("password", "")
    if not password:
        return jsonify({"error": "Password field is required."}), 400

    result = analyze_password(password)
    return jsonify(result)

@app.route("/api/audit-batch", methods=["POST"])
def api_audit_batch():
    """Batch audit multiple passwords from raw text or uploaded list."""
    data = request.get_json() or {}
    raw_text = data.get("passwords_text", "")
    
    if not raw_text:
        return jsonify({"error": "No password list provided."}), 400

    passwords = [line.strip() for line in raw_text.splitlines() if line.strip()]
    if not passwords:
        return jsonify({"error": "Password list contains no valid entries."}), 400

    audit_summary = audit_batch(passwords)
    return jsonify(audit_summary)

@app.route("/api/wordlist-rules", methods=["POST"])
def api_wordlist_rules():
    """
    Demonstrates defensive wordlist pattern mutation rules.
    Used by security teams to model how attackers generate rule-based lists.
    """
    data = request.get_json() or {}
    base_words = data.get("words", ["Company", "Admin", "Pass"])
    append_years = data.get("append_years", True)
    leet_transform = data.get("leet_transform", True)
    capitalize_var = data.get("capitalize_var", True)

    generated = set()

    for word in base_words:
        w = word.strip()
        if not w:
            continue
        
        variations = {w, w.lower(), w.upper()}
        if capitalize_var:
            variations.add(w.capitalize())

        for var in list(variations):
            generated.add(var)
            
            if append_years:
                for yr in ["2023", "2024", "2025", "2026", "123", "!"]:
                    generated.add(f"{var}{yr}")
                    generated.add(f"{var}@{yr}")

            if leet_transform:
                leet_var = var.replace('a', '@').replace('e', '3').replace('i', '1').replace('o', '0').replace('s', '$')
                generated.add(leet_var)
                if append_years:
                    generated.add(f"{leet_var}2024")
                    generated.add(f"{leet_var}!")

    result_list = sorted(list(generated))[:200]  # Limit to 200 samples for UI demonstration
    return jsonify({
        "base_words": base_words,
        "total_generated": len(generated),
        "sample_mutations": result_list
    })

@app.route("/api/export-report", methods=["POST"])
def api_export_report():
    """Generates downloadable Security Audit Report (Markdown / JSON)."""
    data = request.get_json() or {}
    password = data.get("password", "")
    
    if not password:
        return jsonify({"error": "Password analysis data required."}), 400

    analysis = analyze_password(password)
    
    report_md = f"""# Enterprise Password Policy & Security Audit Report

## 1. Executive Summary
- **Audited Target Sample**: `{'*' * len(password)}` (Length: {analysis['password_length']} characters)
- **Security Score**: {analysis['score']} / 100
- **Security Classification**: {analysis['tier']}
- **NIST SP 800-63B Compliance**: {'COMPLIANT' if analysis['nist_status']['is_compliant'] else 'NON-COMPLIANT'}

---

## 2. Entropy & Mathematical Complexity
- **Calculated Entropy**: {analysis['entropy']} bits
- **Character Pool Size**: {analysis['pool_size']} characters

### Theoretical Time-to-Crack Estimates
"""
    for key, spec in analysis['crack_estimates']['scenarios'].items():
        report_md += f"- **{spec['label']}**: {spec['time']}\n"

    report_md += f"""
---

## 3. Policy Violations & Weaknesses
"""
    if analysis['nist_status']['issues']:
        for issue in analysis['nist_status']['issues']:
            report_md += f"- [FAIL] {issue}\n"
    else:
        report_md += "- [PASS] Passed all NIST SP 800-63B basic policy checks.\n"

    if analysis['weaknesses']:
        report_md += "\n### Detected Structural Weaknesses:\n"
        for w in analysis['weaknesses']:
            report_md += f"- **{w['type']}**: {w['desc']}\n"

    report_md += f"""
---

## 4. Blue-Team Recommendations & Remediation
"""
    for rec in analysis['recommendations']:
        report_md += f"1. {rec}\n"

    report_md += "\n\n*Report Generated by Defensive Password Security & Policy Audit System*\n"

    return jsonify({
        "markdown_report": report_md,
        "filename": "security_password_audit_report.md"
    })

if __name__ == "__main__":
    print("Starting Defensive Password Security & Policy Audit Server on http://127.0.0.1:5000")
    app.run(debug=True, port=5000)
