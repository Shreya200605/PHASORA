"""
PHASORA - Privacy-Preserving AI Gateway
=======================================
Main Streamlit Application Entrypoint.
Provides a unified cybersecurity dashboard with Dark Navy & Electric Teal styling,
routing across four core privacy modules:
  1. Live Privacy Gateway
  2. Security Testing Lab
  3. Privacy Analytics
  4. Audit & Privacy Receipts

Designed for hackathon collaboration: UI, Synthetic Datasets, and Evaluation Workspace.
"""

import sys
import os

# Ensure workspace root is in sys.path
WORKSPACE_ROOT = os.path.dirname(os.path.abspath(__file__))
if WORKSPACE_ROOT not in sys.path:
    sys.path.insert(0, WORKSPACE_ROOT)

import streamlit as st
from ui import gateway, security_lab, analytics, audit


def apply_theme():
    """Apply the cybersecurity dark navy and electric teal visual theme."""
    # Embedded core theme ensures dark styling is applied immediately
    embedded_css = """
    <style>
        /* Force dark navy background across Streamlit container */
        .stApp {
            background-color: #070d1e !important;
            color: #f0f6fc !important;
        }
        
        /* Sidebar styling */
        section[data-testid="stSidebar"] {
            background-color: #0b1528 !important;
            border-right: 1px solid #1e3a5f !important;
        }
        
        /* Headers and Typography */
        h1, h2, h3, h4, h5, h6, p, span, label {
            color: #f0f6fc !important;
        }
        
        /* Text inputs and text areas */
        .stTextArea textarea, .stTextInput input, .stSelectbox [data-baseweb="select"] {
            background-color: #0e1e38 !important;
            color: #f0f6fc !important;
            border: 1px solid #1e3a5f !important;
            border-radius: 6px !important;
        }
        
        .stTextArea textarea:focus, .stTextInput input:focus {
            border-color: #00f5d4 !important;
            box-shadow: 0 0 10px rgba(0, 245, 212, 0.25) !important;
        }
        
        /* Radio and selection controls */
        .stRadio div[role="radiogroup"] label {
            color: #e2e8f0 !important;
        }
        
        /* Buttons */
        .stButton button[kind="primary"], .stButton button[data-testid="baseButton-primary"] {
            background: linear-gradient(135deg, #00f5d4 0%, #00b4d8 100%) !important;
            color: #070d1e !important;
            font-weight: 700 !important;
            border: none !important;
            border-radius: 6px !important;
            padding: 8px 20px !important;
            transition: all 0.2s ease-in-out !important;
        }
        
        .stButton button[kind="primary"]:hover {
            box-shadow: 0 0 16px rgba(0, 245, 212, 0.5) !important;
            transform: translateY(-1px) !important;
        }
        
        /* Custom UI classes */
        .phasora-header {
            background: linear-gradient(135deg, #0d1b2a 0%, #112240 50%, #07152d 100%);
            border: 1px solid #1e3a5f;
            border-left: 4px solid #00f5d4;
            border-radius: 8px;
            padding: 18px 24px;
            margin-bottom: 24px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.35);
        }

        .phasora-title {
            font-size: 1.8rem;
            font-weight: 800;
            letter-spacing: 0.05em;
            color: #ffffff !important;
            margin: 0;
            display: flex;
            align-items: center;
            gap: 12px;
        }

        .badge-pill {
            font-size: 0.75rem;
            font-weight: 600;
            letter-spacing: 0.08em;
            padding: 3px 10px;
            border-radius: 20px;
            background: rgba(0, 245, 212, 0.15);
            color: #00f5d4 !important;
            border: 1px solid #00f5d4;
        }

        .phasora-subtitle {
            color: #a0aec0 !important;
            font-size: 0.95rem;
            margin-top: 6px;
            margin-bottom: 0;
        }

        .cyber-card {
            background: #112240;
            border: 1px solid #1e3a5f;
            border-radius: 8px;
            padding: 16px 20px;
            margin-bottom: 16px;
            transition: all 0.2s ease-in-out;
            box-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
        }

        .cyber-card:hover {
            border-color: #00f5d4;
            box-shadow: 0 4px 18px rgba(0, 245, 212, 0.25);
        }

        .cyber-metric-value {
            font-size: 1.85rem;
            font-weight: 700;
            color: #00f5d4 !important;
            line-height: 1.2;
        }

        .cyber-metric-label {
            font-size: 0.8rem;
            text-transform: uppercase;
            letter-spacing: 0.08em;
            color: #a0aec0 !important;
            margin-top: 4px;
        }

        .simulation-banner {
            background: rgba(255, 209, 102, 0.08);
            border: 1px solid #ffd166;
            color: #ffd166 !important;
            border-radius: 6px;
            padding: 10px 16px;
            font-size: 0.88rem;
            margin-bottom: 20px;
        }

        .wire-payload-box {
            background: #091322;
            border: 1px dashed #00b4d8;
            border-radius: 6px;
            padding: 14px 16px;
            font-family: "Courier New", Courier, monospace;
            font-size: 0.88rem;
            color: #48cae4 !important;
            white-space: pre-wrap;
            word-break: break-all;
        }

        .cyber-tag {
            display: inline-block;
            padding: 3px 8px;
            border-radius: 4px;
            font-size: 0.75rem;
            font-weight: 600;
            margin-right: 6px;
            margin-bottom: 4px;
        }

        .tag-redacted {
            background: rgba(0, 245, 212, 0.15);
            color: #00f5d4 !important;
            border: 1px solid #00f5d4;
        }

        .tag-verified {
            background: rgba(0, 180, 216, 0.15);
            color: #48cae4 !important;
            border: 1px solid #00b4d8;
        }
    </style>
    """
    st.markdown(embedded_css, unsafe_allow_html=True)

    # Load additional external styles from assets/style.css if available
    css_file = os.path.join(WORKSPACE_ROOT, "assets", "style.css")
    if os.path.exists(css_file):
        try:
            with open(css_file, "r", encoding="utf-8") as f:
                external_css = f.read()
                st.markdown(f"<style>{external_css}</style>", unsafe_allow_html=True)
        except Exception:
            pass


def main():
    # Page configuration
    st.set_page_config(
        page_title="PHASORA | Privacy-Preserving AI Gateway",
        page_icon="🛡️",
        layout="wide",
        initial_sidebar_state="expanded"
    )

    # Apply professional cybersecurity styling
    apply_theme()

    # Sidebar Navigation & Branding
    with st.sidebar:
        st.markdown("""
            <div style="padding: 10px 0 16px 0; border-bottom: 1px solid #1e3a5f; margin-bottom: 18px;">
                <div style="display: flex; align-items: center; gap: 10px;">
                    <span style="font-size: 2.2rem;">🛡️</span>
                    <div>
                        <div style="font-size: 1.4rem; font-weight: 800; letter-spacing: 0.08em; color: #ffffff;">PHASORA</div>
                        <div style="font-size: 0.72rem; color: #00f5d4; font-weight: 700; letter-spacing: 0.06em;">PRIVACYGUARD AI GATEWAY</div>
                    </div>
                </div>
                <div style="font-size: 0.78rem; color: #a0aec0; margin-top: 8px; line-height: 1.4;">
                    DPDP-Ready Privacy Gateway for Enterprise Large Language Models
                </div>
            </div>
        """, unsafe_allow_html=True)

        st.markdown("<div style='font-size: 0.78rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.08em; color: #a0aec0; margin-bottom: 8px;'>Navigation Menu</div>", unsafe_allow_html=True)

        # 4 Core Dashboard Sections
        navigation_pages = [
            "🛡️ Live Privacy Gateway",
            "🧪 Security Testing Lab",
            "📊 Privacy Analytics",
            "📜 Audit & Privacy Receipts"
        ]

        selected_page = st.radio(
            "Select Dashboard View",
            navigation_pages,
            label_visibility="collapsed"
        )

        st.markdown("---")

        # Gateway Status Widget
        st.markdown("""
            <div class="cyber-card" style="padding: 12px 14px; margin-bottom: 14px;">
                <div style="font-size: 0.72rem; text-transform: uppercase; color: #a0aec0; letter-spacing: 0.06em; margin-bottom: 4px;">Gateway Status</div>
                <div style="display: flex; align-items: center; gap: 8px;">
                    <span style="height: 10px; width: 10px; background-color: #00f5d4; border-radius: 50%; display: inline-block; box-shadow: 0 0 8px #00f5d4;"></span>
                    <span style="font-size: 0.88rem; font-weight: 700; color: #ffffff;">OPERATIONAL</span>
                </div>
                <div style="font-size: 0.74rem; color: #a0aec0; margin-top: 8px; line-height: 1.5;">
                    Mode: <strong style="color:#00f5d4;">Synthetic Guard v1.0</strong><br>
                    Policy: <strong style="color:#ffffff;">DPDP Act 2023</strong><br>
                    Backend: <em>Pre-Integration Simulator</em>
                </div>
            </div>
        """, unsafe_allow_html=True)

        # Hackathon Team Footnote
        st.markdown("""
            <div style="font-size: 0.72rem; color: #718096; line-height: 1.4; border-top: 1px solid #1e3a5f; padding-top: 10px;">
                <strong>PHASORA Shared Repository</strong><br>
                UI, Synthetic Datasets & Evaluation Workspace<br>
                Core PII Engine under parallel development.
            </div>
        """, unsafe_allow_html=True)

    # Route to the selected page module
    if selected_page == "🛡️ Live Privacy Gateway":
        gateway.render()
    elif selected_page == "🧪 Security Testing Lab":
        security_lab.render()
    elif selected_page == "📊 Privacy Analytics":
        analytics.render()
    elif selected_page == "📜 Audit & Privacy Receipts":
        audit.render()


if __name__ == "__main__":
    main()

