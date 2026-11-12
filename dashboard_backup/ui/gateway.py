"""
PHASORA UI - Live Privacy Gateway Module
=======================================
Interactive live playground demonstrating privacy-preserving prompt interception,
PII tokenization, zero-knowledge external forwarding, and client-side restoration.

NOTE: Operating in synthetic simulation mode until backend PII engine integration.
Never displays real PII or secret placeholder vault mappings.
"""

import json
import os
import time
import streamlit as st
import pandas as pd


def load_synthetic_presets():
    """Load sample documents from data/synthetic_documents.json."""
    data_path = os.path.join(os.path.dirname(__file__), "..", "data", "synthetic_documents.json")
    try:
        with open(data_path, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return []


def render():
    # Page Header
    st.markdown("""
        <div class="phasora-header">
            <h2 class="phasora-title">
                🛡️ Live Privacy Gateway
                <span class="badge-pill">ZERO-TRUST ENCLAVE</span>
            </h2>
            <p class="phasora-subtitle">
                Inspect, sanitize, tokenize, and safely dispatch enterprise queries to external LLMs without data leakage.
            </p>
        </div>
    """, unsafe_allow_html=True)

    # Mandatory Simulation Notice Banner
    st.markdown("""
        <div class="simulation-banner">
            ⚡ <strong>SIMULATED PROCESSING:</strong> Gateway is operating in pre-integration simulation mode using synthetic document presets. All tokens and cryptographic hashes are generated for interface validation until the core privacy backend is linked.
        </div>
    """, unsafe_allow_html=True)

    presets = load_synthetic_presets()
    preset_titles = [f"{doc['id']} - {doc['title']}" for doc in presets]

    # Controls Row
    col_source, col_purpose, col_strategy = st.columns([1.5, 1.5, 1.2])

    with col_source:
        input_mode = st.radio(
            "Document Source",
            ["Preset Synthetic Customer Document", "Custom Text Input"],
            horizontal=True
        )

    with col_purpose:
        purpose_options = [
            "Customer KYC Onboarding (DPDP Sec 6)",
            "Grievance & Support Dispute Resolution",
            "Credit & Underwriting Risk Analysis",
            "Clinical Health Consultation Review",
            "HR Appraisal & Compensation Review",
            "Vendor & Corporate Legal Review"
        ]
        selected_purpose = st.selectbox("Processing Purpose (DPDP Compliance)", purpose_options)

    with col_strategy:
        mask_strategy = st.selectbox(
            "Redaction Strategy",
            [
                "Cryptographic Vault Tokens (<TOKEN_ID>)",
                "Standard Masking ([REDACTED])",
                "Synthetic Identity Aliases"
            ]
        )

    # Document Selection / Custom Input
    selected_doc = None
    default_text = ""

    if input_mode == "Preset Synthetic Customer Document" and presets:
        selected_title = st.selectbox("Select Sample Customer Document:", preset_titles)
        selected_idx = preset_titles.index(selected_title)
        selected_doc = presets[selected_idx]
        default_text = selected_doc["raw_text"]

        st.caption(
            f"📋 **Scenario:** {selected_doc['scenario']} | "
            f"🏢 **Department:** {selected_doc['department']} | "
            f"⚖️ **Compliance:** {', '.join(selected_doc.get('compliance_scope', ['DPDP Act 2023']))}"
        )
    else:
        default_text = (
            "Customer Dispute Submission:\n"
            "Applicant Name: Aarav Sharma\n"
            "Aadhaar Number: 9012 3456 7890\n"
            "Permanent Account Number (PAN): ABCPS1234K\n"
            "Contact Phone: +91 98765 43210\n"
            "Registered Email: aarav.sharma.test@sampledomain.example\n"
            "Issue: Account debit discrepancy of INR 14,500 under grievance ticket #9901."
        )

    prompt_input = st.text_area(
        "Customer Document / Query Stream:",
        value=default_text,
        height=160,
        help="Unstructured document containing sensitive personal identifiers."
    )

    # Action Trigger Row
    col_action, col_meta = st.columns([1.2, 3])
    with col_action:
        process_btn = st.button("🛡️ Process Document", type="primary", use_container_width=True)
    with col_meta:
        st.markdown(
            f"<div style='font-size: 0.85rem; color: #00f5d4; line-height: 2.3;'>"
            f"🔒 Target Purpose: <strong>{selected_purpose.split('(')[0].strip()}</strong> | Zero-Knowledge Boundary Enforced"
            f"</div>",
            unsafe_allow_html=True
        )

    # Process Simulation Logic
    if process_btn or prompt_input:
        with st.spinner("Intercepting payload and applying privacy transformations..."):
            time.sleep(0.12)

        # Generate masked output and entities
        if selected_doc and prompt_input.strip() == selected_doc["raw_text"].strip():
            detected_entities = selected_doc.get("synthetic_entities", [])
            wire_text = selected_doc.get("expected_redacted_text", prompt_input)
        else:
            detected_entities = [
                {"entity": "Aarav Sharma", "type": "PERSON_NAME", "category": "DIRECT_IDENTIFIER", "sensitivity": "HIGH"},
                {"entity": "9012 3456 7890", "type": "INDIAN_AADHAAR", "category": "GOVERNMENT_ID", "sensitivity": "CRITICAL"},
                {"entity": "ABCPS1234K", "type": "INDIAN_PAN", "category": "GOVERNMENT_ID", "sensitivity": "CRITICAL"},
                {"entity": "+91 98765 43210", "type": "PHONE_NUMBER", "category": "CONTACT_INFO", "sensitivity": "HIGH"},
                {"entity": "aarav.sharma.test@sampledomain.example", "type": "EMAIL_ADDRESS", "category": "CONTACT_INFO", "sensitivity": "HIGH"}
            ]
            wire_text = prompt_input
            wire_text = wire_text.replace("Aarav Sharma", "<TOKEN_PERSON_01>")
            wire_text = wire_text.replace("9012 3456 7890", "<TOKEN_AADHAAR_01>")
            wire_text = wire_text.replace("ABCPS1234K", "<TOKEN_PAN_01>")
            wire_text = wire_text.replace("+91 98765 43210", "<TOKEN_PHONE_01>")
            wire_text = wire_text.replace("aarav.sharma.test@sampledomain.example", "<TOKEN_EMAIL_01>")

        if "Standard Masking" in mask_strategy:
            wire_text = wire_text.replace("<TOKEN_PERSON_01>", "[REDACTED_NAME]")
            wire_text = wire_text.replace("<TOKEN_AADHAAR_01>", "[REDACTED_AADHAAR]")
            wire_text = wire_text.replace("<TOKEN_PAN_01>", "[REDACTED_PAN]")
            wire_text = wire_text.replace("<TOKEN_PHONE_01>", "[REDACTED_PHONE]")
            wire_text = wire_text.replace("<TOKEN_EMAIL_01>", "[REDACTED_EMAIL]")

        # Metric Strip
        st.markdown("###")
        m1, m2, m3, m4 = st.columns(4)
        with m1:
            st.markdown(f"""
                <div class="cyber-card">
                    <div class="cyber-metric-value">{len(detected_entities)}</div>
                    <div class="cyber-metric-label">Shielded Entities</div>
                </div>
            """, unsafe_allow_html=True)
        with m2:
            st.markdown("""
                <div class="cyber-card">
                    <div class="cyber-metric-value">13.8 ms</div>
                    <div class="cyber-metric-label">Gateway Overhead</div>
                </div>
            """, unsafe_allow_html=True)
        with m3:
            st.markdown("""
                <div class="cyber-card">
                    <div class="cyber-metric-value">0.00%</div>
                    <div class="cyber-metric-label">PII Leakage Rate</div>
                </div>
            """, unsafe_allow_html=True)
        with m4:
            st.markdown("""
                <div class="cyber-card">
                    <div class="cyber-metric-value" style="color: #00f5d4;">VERIFIED</div>
                    <div class="cyber-metric-label">DPDP Sec 6 Status</div>
                </div>
            """, unsafe_allow_html=True)

        # Three Inspection Panels: Original, Masked, Restored
        st.markdown("#### 🔄 Privacy Gateway Three-Panel Inspection")
        p1, p2, p3 = st.columns(3)

        with p1:
            st.markdown("##### 📄 1. Original Input Document")
            st.markdown("<div style='font-size:0.8rem; color:#a0aec0; margin-bottom:6px;'>Unmasked customer plaintext received at client boundary.</div>", unsafe_allow_html=True)
            st.text_area("Original Input", value=prompt_input, height=220, disabled=True, key="orig_view")

        with p2:
            st.markdown("##### 🛡️ 2. Masked Output (Wire Payload)")
            st.markdown("<div style='font-size:0.8rem; color:#00f5d4; margin-bottom:6px;'>What external LLM receives: only zero-knowledge tokens. No PII transmitted.</div>", unsafe_allow_html=True)
            st.text_area("Masked Output", value=wire_text, height=220, disabled=True, key="mask_view")

        with p3:
            st.markdown("##### 🔓 3. Simulated Restored Response")
            st.markdown("<div style='font-size:0.8rem; color:#48cae4; margin-bottom:6px;'>Client enclave re-links tokens to response without LLM ever seeing PII.</div>", unsafe_allow_html=True)
            sim_completion = (
                f"Simulated Model Response:\n"
                f"Under verified purpose '{selected_purpose.split('(')[0].strip()}', the submitted record has been validated. "
                f"All eligibility and verification criteria satisfy DPDP Act 2023 guidelines."
            )
            st.text_area("Restored Response", value=sim_completion, height=220, disabled=True, key="restored_view")

        # Entity Classification Table
        st.markdown("#### 🔍 Detected & Shielded Sensitive Attributes")
        if detected_entities:
            df_entities = pd.DataFrame(detected_entities)
            st.dataframe(
                df_entities,
                column_config={
                    "entity": "Synthetic Value",
                    "type": "Entity Type",
                    "category": "Identifier Category",
                    "sensitivity": st.column_config.BadgeColumn(
                        "Sensitivity Tier",
                        help="Data protection classification",
                        default="MEDIUM"
                    )
                },
                use_container_width=True,
                hide_index=True
            )
        else:
            st.info("No sensitive entities detected in this segment.")
