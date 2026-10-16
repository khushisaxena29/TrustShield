"""
app.py
------
STEP 6 of the build order — connects every module into the UI.

TrustShield - "Think Before You Click."
Run with:  streamlit run app.py
"""

import os
import streamlit as st
import plotly.graph_objects as go
import pandas as pd

from modules.text_analyzer import analyze_text, classify_text
from modules.url_analyzer import analyze_url, is_url_like
from modules.risk_engine import (
    score_text, score_url, combine_scores,
    get_risk_level, get_risk_color, get_recommendations,
)
from modules.qr_scanner import decode_qr_from_image
from utils.helpers import save_scan, load_history, get_stats, clear_history, load_demo_messages
from report_generator import generate_report

# ---------------------------------------------------------------------
# Page config
# ---------------------------------------------------------------------
st.set_page_config(
    page_title="TrustShield",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ---------------------------------------------------------------------
# Sidebar
# ---------------------------------------------------------------------
logo_path = os.path.join("assets", "logo.png")
if os.path.exists(logo_path):
    st.sidebar.image(logo_path, width=80)
st.sidebar.markdown("## TrustShield")
st.sidebar.caption("Think Before You Click.")
page = st.sidebar.radio(
    "Navigate",
    ["Dashboard", "Message Scanner", "URL Scanner", "QR Scanner", "Scan History", "About"],
    label_visibility="collapsed",
)


# ---------------------------------------------------------------------
# Shared render helpers
# ---------------------------------------------------------------------
def render_risk_box(score, level):
    color = get_risk_color(level)
    col1, col2 = st.columns(2)
    with col1:
        st.metric("Risk Score", f"{score}/100")
    with col2:
        st.markdown(f"**Risk Level:** :{color}[{level}]")


def render_breakdown(breakdown):
    if not breakdown:
        st.info("No risk factors detected.")
        return
    for label, points in breakdown:
        st.write(f"**{label}**  `+{points}`")


def render_recommendations(threat_category):
    dont, do = get_recommendations(threat_category)
    col1, col2 = st.columns(2)
    with col1:
        st.markdown("#### What NOT to do")
        for item in dont:
            st.markdown(f"- {item}")
    with col2:
        st.markdown("#### What to do")
        for item in do:
            st.markdown(f"- {item}")
    return dont, do


def render_download_report(input_type, raw_input, score, level, category, breakdown, dont, do):
    report_text = generate_report(input_type, raw_input, score, level, category, breakdown, dont, do)
    st.download_button(
        "Download Incident Report",
        data=report_text,
        file_name=f"trustshield_report_{level.lower()}.txt",
        mime="text/plain",
    )


# =======================================================================
# PAGE: DASHBOARD
# =======================================================================
if page == "Dashboard":
    st.title("TrustShield")
    st.caption("Think Before You Click.")
    st.markdown("---")

    stats = get_stats()
    c1, c2, c3, c4, c5 = st.columns(5)
    c1.metric("Total Scans", stats["total_scans"])
    c2.metric("Safe", stats["safe_count"])
    c3.metric("Medium Risk", stats["medium_count"])
    c4.metric("High Risk", stats["high_count"])
    c5.metric("Critical", stats["critical_count"])

    st.markdown("### Risk Distribution")
    if stats["total_scans"] > 0:
        chart_df = pd.DataFrame({
            "Risk Level": ["Safe", "Medium", "High", "Critical"],
            "Count": [stats["safe_count"], stats["medium_count"], stats["high_count"], stats["critical_count"]],
        })
        colors = ["#2ecc71", "#f1c40f", "#e67e22", "#e74c3c"]
        fig = go.Figure(data=[go.Bar(
            x=chart_df["Risk Level"], y=chart_df["Count"],
            marker_color=colors, text=chart_df["Count"], textposition="auto",
        )])
        fig.update_layout(height=380, margin=dict(t=20, b=20, l=20, r=20))
        st.plotly_chart(fig, use_container_width=True)
    else:
        st.info("No scans yet. Run a Message, URL, or QR scan to see stats here.")

    st.markdown("### Recent Scans")
    recent = load_history().head(5)
    if not recent.empty:
        st.dataframe(recent, use_container_width=True, hide_index=True)
    else:
        st.caption("Nothing scanned yet.")

# =======================================================================
# PAGE: MESSAGE SCANNER
# =======================================================================
elif page == "Message Scanner":
    st.title("Message Scanner")
    st.caption("Paste an SMS, email, or WhatsApp message to check for scam indicators.")
    st.markdown("---")

    demo_cases = load_demo_messages()
    with st.expander("Try a demo message"):
        demo_choice = st.selectbox("Pick a sample", ["-- select --"] + list(demo_cases.keys()))
        if demo_choice != "-- select --":
            st.session_state["message_input"] = demo_cases[demo_choice]

    message_text = st.text_area(
        "Paste the message here",
        value=st.session_state.get("message_input", ""),
        height=150,
        key="message_input",
    )

    if st.button("Analyze Message", type="primary"):
        indicators = analyze_text(message_text)

        if indicators.get("empty_input"):
            st.warning("Please enter a message to analyze.")
        else:
            msg_score, msg_breakdown = score_text(indicators)

            # If the message contains links, fold in the worst link's score
            url_breakdown = []
            worst_url_score = 0
            for found_url in indicators["urls_found"][:3]:
                url_indicators = analyze_url(found_url)
                u_score, u_breakdown = score_url(url_indicators)
                if u_score > worst_url_score:
                    worst_url_score = u_score
                    url_breakdown = u_breakdown

            final_score = combine_scores(msg_score, worst_url_score)
            risk_level = get_risk_level(final_score)
            category = classify_text(indicators)
            full_breakdown = msg_breakdown + url_breakdown

            save_scan("Message", message_text, final_score, risk_level, category)

            st.markdown("### Result")
            col1, col2 = st.columns([1, 2])
            with col1:
                render_risk_box(final_score, risk_level)
                st.metric("Threat Category", category)
            with col2:
                st.markdown("#### Red Flags")
                if indicators["indicators"]:
                    for flag in indicators["indicators"]:
                        st.markdown(f"- {flag}")
                else:
                    st.success("No red flags detected in the text.")

            with st.expander("Risk Score Breakdown", expanded=True):
                render_breakdown(full_breakdown)

            st.markdown("### Safety Recommendations")
            dont, do = render_recommendations(category)
            render_download_report("Message", message_text, final_score, risk_level, category, full_breakdown, dont, do)

# =======================================================================
# PAGE: URL SCANNER
# =======================================================================
elif page == "URL Scanner":
    st.title("URL Scanner")
    st.caption("Paste a URL to check its structure for phishing indicators.")
    st.markdown("---")

    url_text = st.text_input("Enter a URL", placeholder="https://example.com/login")

    if st.button("Analyze URL", type="primary"):
        indicators = analyze_url(url_text)

        if indicators.get("empty_input"):
            st.warning("Please enter a URL to analyze.")
        else:
            url_score, url_breakdown = score_url(indicators)
            risk_level = get_risk_level(url_score)

            if indicators["brand_impersonation"]:
                category = "Phishing"
            elif not indicators["valid"]:
                category = "Unknown/Suspicious"
            elif url_score <= 30:
                category = "Safe"
            else:
                category = "Phishing"

            save_scan("URL", url_text, url_score, risk_level, category)

            st.markdown("### Result")
            col1, col2 = st.columns([1, 2])
            with col1:
                render_risk_box(url_score, risk_level)
                st.metric("Domain", indicators["domain"] or "N/A")
            with col2:
                st.markdown("#### Red Flags")
                if indicators["indicators"]:
                    for flag in indicators["indicators"]:
                        st.markdown(f"- {flag}")
                else:
                    st.success("No red flags detected in this URL.")

            with st.expander("Risk Score Breakdown", expanded=True):
                render_breakdown(url_breakdown)

            st.markdown("### Safety Recommendations")
            dont, do = render_recommendations(category)
            render_download_report("URL", url_text, url_score, risk_level, category, url_breakdown, dont, do)

# =======================================================================
# PAGE: QR SCANNER
# =======================================================================
elif page == "QR Scanner":
    st.title("QR Scanner")
    st.caption("Upload a QR code image. TrustShield decodes it and analyzes the content automatically.")
    st.markdown("---")

    uploaded_image = st.file_uploader("Upload a QR code image", type=["png", "jpg", "jpeg"])

    if uploaded_image is not None:
        st.image(uploaded_image, width=200, caption="Uploaded QR code")

        if st.button("Decode & Analyze", type="primary"):
            decoded_text = decode_qr_from_image(uploaded_image)

            if not decoded_text:
                st.error("Could not detect a QR code in this image. Try a clearer photo.")
            else:
                st.markdown(f"**Decoded content:** `{decoded_text}`")

                if is_url_like(decoded_text):
                    indicators = analyze_url(decoded_text)
                    score, breakdown = score_url(indicators)
                    category = "Phishing" if (indicators["brand_impersonation"] or score > 30) else "Safe"
                    flags = indicators["indicators"]
                    input_type = "QR Code (URL)"
                else:
                    indicators = analyze_text(decoded_text)
                    score, breakdown = score_text(indicators)
                    category = classify_text(indicators)
                    flags = indicators["indicators"]
                    input_type = "QR Code (Text)"

                risk_level = get_risk_level(score)
                save_scan(input_type, decoded_text, score, risk_level, category)

                st.markdown("### Result")
                col1, col2 = st.columns([1, 2])
                with col1:
                    render_risk_box(score, risk_level)
                    st.metric("Threat Category", category)
                with col2:
                    st.markdown("#### Red Flags")
                    if flags:
                        for flag in flags:
                            st.markdown(f"- {flag}")
                    else:
                        st.success("No red flags detected.")

                with st.expander("Risk Score Breakdown", expanded=True):
                    render_breakdown(breakdown)

                st.markdown("### Safety Recommendations")
                dont, do = render_recommendations(category)
                render_download_report(input_type, decoded_text, score, risk_level, category, breakdown, dont, do)

# =======================================================================
# PAGE: SCAN HISTORY
# =======================================================================
elif page == "Scan History":
    st.title("Scan History")
    st.markdown("---")

    history_df = load_history()
    if not history_df.empty:
        st.dataframe(history_df, use_container_width=True, hide_index=True)
        st.markdown("---")
        if st.button("Clear History"):
            clear_history()
            st.success("History cleared.")
            st.rerun()
    else:
        st.info("No scans yet. Go to Message Scanner, URL Scanner, or QR Scanner to run your first scan.")

# =======================================================================
# PAGE: ABOUT
# =======================================================================
elif page == "About":
    st.title("About TrustShield")
    st.markdown("---")
    st.markdown("""
    **TrustShield** is an explainable AI-powered digital safety tool that helps
    people spot scams, phishing attempts, and suspicious URLs — including
    ones hidden inside QR codes — before they act on them.

    Unlike a black-box classifier, TrustShield shows **exactly why** something
    was flagged — every point in the risk score is tied to a specific, visible red flag.

    #### How scoring works
    - **0–30 → SAFE**
    - **31–60 → MEDIUM**
    - **61–80 → HIGH**
    - **81–100 → CRITICAL**

    #### Built with
    Python · Streamlit · Plotly · OpenCV (QR decoding) · tldextract/regex

    #### Disclaimer
    TrustShield is a rule-based heuristic tool built for a hackathon demo.
    It is **not** a substitute for official verification through your bank
    or service provider.
    """)