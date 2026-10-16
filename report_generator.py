"""
report_generator.py
---------------------
STEP 5 of the build order.

Builds a plain-text "incident report" summarizing one scan result,
suitable for st.download_button() in app.py. Kept as plain text
(not PDF) on purpose - zero extra dependencies, zero chance of
breaking during the demo.

Used by: app.py
"""

from datetime import datetime


def generate_report(input_type, raw_input, risk_score, risk_level, category, breakdown, dont_list, do_list):
    """
    Build a formatted text report string for one scan result.

    Args:
        input_type (str): 'Message', 'URL', or 'QR Code'
        raw_input (str): the original scanned content
        risk_score (int): 0-100
        risk_level (str): SAFE / MEDIUM / HIGH / CRITICAL
        category (str): threat category label
        breakdown (list[tuple]): [(label, points), ...]
        dont_list (list[str]): "what not to do" recommendations
        do_list (list[str]): "what to do" recommendations

    Returns:
        str: the full report, ready to write to a .txt file
    """
    lines = []
    lines.append("=" * 60)
    lines.append("TRUSTSHIELD SECURITY SCAN REPORT")
    lines.append("Think Before You Click.")
    lines.append("=" * 60)
    lines.append(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")
    lines.append(f"Input Type: {input_type}")
    lines.append("")
    lines.append("SCANNED CONTENT")
    lines.append("-" * 60)
    lines.append((raw_input or "").strip()[:500])
    lines.append("")
    lines.append("RESULT")
    lines.append("-" * 60)
    lines.append(f"RISK SCORE : {risk_score}/100")
    lines.append(f"RISK LEVEL : {risk_level}")
    lines.append(f"CATEGORY   : {category}")
    lines.append("")
    lines.append("RISK BREAKDOWN")
    lines.append("-" * 60)
    if breakdown:
        for label, points in breakdown:
            lines.append(f"  {label:<45} +{points}")
    else:
        lines.append("  No risk factors detected.")
    lines.append("")
    lines.append("WHAT NOT TO DO")
    lines.append("-" * 60)
    for item in dont_list:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append("WHAT TO DO")
    lines.append("-" * 60)
    for item in do_list:
        lines.append(f"  - {item}")
    lines.append("")
    lines.append("=" * 60)
    lines.append("This is an automated heuristic scan, not a substitute for")
    lines.append("verification through your bank or service provider.")
    lines.append("=" * 60)

    return "\n".join(lines)


