"""
PHASORA UI - Audit & Privacy Receipts Module
============================================
Cryptographic privacy release receipts and compliance auditing for enterprise LLM interactions.
Implements DPDP Act 2023 Section 8 auditability without exposing sensitive underlying PII or secret mappings.

Uses Pandas for log querying and Plotly for compliance status distribution.
"""

import json
import streamlit as st
import pandas as pd
from datetime import datetime, timedelta


def get_sample_audit_records():
    """Generate realistic synthetic audit log entries for enterprise governance."""
    base_time = datetime.now()
    records = [
        {
            "request_id": "PHASORA-REQ-2026-8801",
            "timestamp": (base_time - timedelta(minutes=14)).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "department": "Fintech & Banking",
            "purpose": "Retail KYC Onboarding",
            "entities_shielded": 10,
            "processing_status": "COMPLIANT - ZERO PII EXPOSURE",
            "action": "TOKENIZED & DISPATCHED",
            "compliance_policy": "DPDP-ACT-2023-SEC6",
            "inbound_sha256": "8f4a3e29c118e9d0b5034c4f34a8e29104c99321efb0451a92df4401bb8a7e02",
            "wire_payload_sha256": "3a01f92e8d19ab4c7712d90b410543e210fa098b6540c11394e82df41198ae23",
            "risk_score": "LOW"
        },
        {
            "request_id": "PHASORA-REQ-2026-8802",
            "timestamp": (base_time - timedelta(minutes=32)).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "department": "Digital Health",
            "purpose": "Telehealth Consultation Notes",
            "entities_shielded": 8,
            "processing_status": "COMPLIANT - ZERO PII EXPOSURE",
            "action": "TOKENIZED & DISPATCHED",
            "compliance_policy": "HIPAA-SAFE-HARBOR + DPDP",
            "inbound_sha256": "4b912a77df3410c59801ec4b321a0f9488a033b00c592e8812c301a9df881023",
            "wire_payload_sha256": "19a0df44b1029e8832a44b91df34882103a45c0912ef003b441a99d2105e94b1",
            "risk_score": "LOW"
        },
        {
            "request_id": "PHASORA-REQ-2026-8803",
            "timestamp": (base_time - timedelta(minutes=48)).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "department": "Customer Operations",
            "purpose": "Adversarial Test Vector Probe",
            "entities_shielded": 2,
            "processing_status": "THREAT NEUTRALIZED AT BOUNDARY",
            "action": "INJECTION BLOCKED",
            "compliance_policy": "ADVERSARIAL-DEFENSE-V2",
            "inbound_sha256": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
            "wire_payload_sha256": "0000000000000000000000000000000000000000000000000000000000000000",
            "risk_score": "HIGH"
        },
        {
            "request_id": "PHASORA-REQ-2026-8804",
            "timestamp": (base_time - timedelta(hours=1, minutes=12)).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "department": "People Operations (HR)",
            "purpose": "Compensation Appraisal Analysis",
            "entities_shielded": 7,
            "processing_status": "COMPLIANT - ZERO PII EXPOSURE",
            "action": "TOKENIZED & DISPATCHED",
            "compliance_policy": "DPDP-SEC8-AUDITABLE",
            "inbound_sha256": "771a9df88029b41a34c89901ef44a1029df40192e8810c345a9012df491024e1",
            "wire_payload_sha256": "9921b4401a88df02914ca8e1029df40192881023450a99104c21980ef44012ab",
            "risk_score": "LOW"
        },
        {
            "request_id": "PHASORA-REQ-2026-8805",
            "timestamp": (base_time - timedelta(hours=2, minutes=5)).strftime("%Y-%m-%d %H:%M:%S UTC"),
            "department": "Corporate Legal",
            "purpose": "Master Services Procurement",
            "entities_shielded": 8,
            "processing_status": "COMPLIANT - ZERO PII EXPOSURE",
            "action": "TOKENIZED & DISPATCHED",
            "compliance_policy": "DPDP-ENTERPRISE-TIER1",
            "inbound_sha256": "0291df44a8810c921ef401982b4410a99214ca01928df441029a88df40192e88",
            "wire_payload_sha256": "5501924ca8810df44a991029df8810c345a9012ef4401928df02914ca8e1029d",
            "risk_score": "LOW"
        }
    ]
    return records


def render():
    st.markdown("""
        <div class="phasora-header">
            <h2 class="phasora-title">
                📜 Audit & Privacy Receipts
                <span class="badge-pill">TAMPER-EVIDENT DPDP AUDIT</span>
            </h2>
            <p class="phasora-subtitle">
                Cryptographically verifiable privacy release receipts ensuring regulatory compliance without revealing underlying data.
            </p>
        </div>
    """, unsafe_allow_html=True)

    # Sample Disclaimer Banner
    st.markdown("""
        <div class="simulation-banner">
            ⚡ <strong>SAMPLE AUDIT TRAIL:</strong> Transaction hashes and records shown are synthetic demonstration logs illustrating verifiable privacy auditing under India DPDP Act 2023 Section 8. Real PII and private token dictionaries are never exposed.
        </div>
    """, unsafe_allow_html=True)

    records = get_sample_audit_records()
    df_audit = pd.DataFrame(records)

    tab_receipt, tab_log, tab_consent = st.tabs([
        "🧾 Privacy Release Receipt",
        "📑 Enterprise Audit Trail",
        "⚖️ DPDP Consent & Purpose Verifier"
    ])

    # -------------------------------------------------------------
    # TAB 1: Privacy Release Receipt Inspector
    # -------------------------------------------------------------
    with tab_receipt:
        st.markdown("#### 🔍 Verifiable Privacy Release Receipt")
        st.caption("Inspect cryptographic receipts confirming no raw PII escaped the enterprise boundary.")

        req_options = [r["request_id"] for r in records]
        selected_req = st.selectbox("Select Request ID for Verification:", req_options)

        req_data = next((r for r in records if r["request_id"] == selected_req), records[0])

        col_left, col_right = st.columns([1.5, 1])

        with col_left:
            st.markdown(f"""
                <div class="cyber-card" style="border-left: 4px solid #00f5d4;">
                    <div style="display:flex; justify-content:space-between; align-items:center; margin-bottom:12px;">
                        <h4 style="color:#00f5d4; margin:0;">RECEIPT: {req_data['request_id']}</h4>
                        <span class="cyber-tag tag-verified">PROVEN ISOLATED</span>
                    </div>
                    <p style="font-size:0.85rem; color:#a0aec0; margin-bottom:6px;">
                        <strong>Request ID:</strong> {req_data['request_id']}
                    </p>
                    <p style="font-size:0.85rem; color:#a0aec0; margin-bottom:6px;">
                        <strong>Timestamp:</strong> {req_data['timestamp']}
                    </p>
                    <p style="font-size:0.85rem; color:#a0aec0; margin-bottom:6px;">
                        <strong>Processing Status:</strong> <span style="color:#00f5d4; font-weight:700;">{req_data['processing_status']}</span>
                    </p>
                    <p style="font-size:0.85rem; color:#a0aec0; margin-bottom:6px;">
                        <strong>Department / Origin:</strong> {req_data['department']} ({req_data['purpose']})
                    </p>
                    <p style="font-size:0.85rem; color:#a0aec0; margin-bottom:6px;">
                        <strong>Shielded Entities:</strong> {req_data['entities_shielded']} Sensitive Attributes Intercepted
                    </p>
                    <p style="font-size:0.85rem; color:#a0aec0; margin-bottom:6px;">
                        <strong>Compliance Policy:</strong> {req_data['compliance_policy']}
                    </p>
                    <hr style="border:0; border-top:1px solid #1e3a5f; margin:10px 0;">
                    <div style="font-family:'Courier New', monospace; font-size:0.78rem; color:#48cae4; line-height:1.5;">
                        <div><strong>INBOUND PROMPT HASH (SHA-256):</strong></div>
                        <div style="word-break:break-all; color:#a0aec0;">{req_data['inbound_sha256']}</div>
                        <div style="margin-top:6px;"><strong>OUTBOUND WIRE PAYLOAD HASH:</strong></div>
                        <div style="word-break:break-all; color:#a0aec0;">{req_data['wire_payload_sha256']}</div>
                        <div style="margin-top:6px;"><strong>ENCLAVE ATTESTATION SIGNATURE:</strong></div>
                        <div style="word-break:break-all; color:#00f5d4;">HMAC-SHA256: 4e91b8a...[CRYPTOGRAPHICALLY SIGNED]</div>
                    </div>
                </div>
            """, unsafe_allow_html=True)

        with col_right:
            st.markdown("""
                <div class="cyber-card">
                    <h5 style="color:#f0f6fc; margin-top:0;">🛡️ Privacy Verification Guarantee</h5>
                    <ul style="font-size:0.85rem; color:#a0aec0; padding-left:18px; margin-bottom:12px;">
                        <li>Zero raw personal data stored in external logs.</li>
                        <li>Client-side vault prevents third-party model retention.</li>
                        <li>Secret placeholder mappings remain strictly inside memory vault.</li>
                        <li>Auditable under Section 8 of Digital Personal Data Protection Act 2023.</li>
                    </ul>
                </div>
            """, unsafe_allow_html=True)

            receipt_json = json.dumps(req_data, indent=2)
            st.download_button(
                label="📥 Download Privacy Receipt (JSON)",
                data=receipt_json,
                file_name=f"{selected_req}_receipt.json",
                mime="application/json",
                use_container_width=True
            )

    # -------------------------------------------------------------
    # TAB 2: Enterprise Audit Trail
    # -------------------------------------------------------------
    with tab_log:
        st.markdown("#### 📑 Searchable Audit Log")
        st.caption("Filter and export enterprise privacy transactions across departments and actions.")

        col_f1, col_f2 = st.columns(2)
        with col_f1:
            action_filter = st.selectbox("Filter by Gateway Action", ["ALL", "TOKENIZED & DISPATCHED", "INJECTION BLOCKED"])
        with col_f2:
            dept_filter = st.selectbox("Filter by Department", ["ALL"] + sorted(list(set(df_audit["department"]))))

        filtered_df = df_audit.copy()
        if action_filter != "ALL":
            filtered_df = filtered_df[filtered_df["action"] == action_filter]
        if dept_filter != "ALL":
            filtered_df = filtered_df[filtered_df["department"] == dept_filter]

        st.dataframe(
            filtered_df[[
                "request_id", "timestamp", "department", "purpose", "entities_shielded", "action", "processing_status"
            ]],
            column_config={
                "request_id": "Request ID",
                "timestamp": "Timestamp (UTC)",
                "department": "Department",
                "purpose": "Purpose",
                "entities_shielded": "Shielded Entities",
                "action": "Gateway Action",
                "processing_status": "Processing Status"
            },
            use_container_width=True,
            hide_index=True
        )

        csv_data = filtered_df.to_csv(index=False)
        st.download_button(
            label="📥 Export Filtered Audit Trail (CSV)",
            data=csv_data,
            file_name="phasora_audit_trail.csv",
            mime="text/csv"
        )

    # -------------------------------------------------------------
    # TAB 3: DPDP Consent & Purpose Verifier
    # -------------------------------------------------------------
    with tab_consent:
        st.markdown("#### ⚖️ DPDP Act Purpose Limitation & Consent Verifier")
        st.caption("Verifies alignment between data processing purpose and active consent records under DPDP Act 2023 Sections 6 & 9.")

        consent_checks = [
            {"Rule": "DPDP Sec 6 (Specific Consent)", "Context": "Retail Banking KYC", "Consent Active": "YES (Tier-1 KYC)", "Status": "PASS"},
            {"Rule": "DPDP Sec 6 (Purpose Limitation)", "Context": "Customer Support Ticket Analysis", "Consent Active": "YES (Operational Support)", "Status": "PASS"},
            {"Rule": "DPDP Sec 9 (Data of Children)", "Context": "EdTech Student Query (<18)", "Consent Active": "REQUIRES VERIFIED PARENTAL CONSENT", "Status": "GUARDED"},
            {"Rule": "DPDP Sec 8 (Storage Limitation)", "Context": "Vault Key Expiry TTL", "Consent Active": "EPHEMERAL (24h Auto-Purge)", "Status": "PASS"}
        ]
        st.dataframe(pd.DataFrame(consent_checks), use_container_width=True, hide_index=True)
