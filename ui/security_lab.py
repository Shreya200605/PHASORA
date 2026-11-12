"""
PHASORA UI - Security Testing Lab Module
========================================
Interactive Red-Teaming, PII Leakage Probes, and Placeholder Manipulation Testing.

Features:
- Deterministic, lightweight rule-based evaluation engine.
- Dynamic detection and sanitization for MANIP-01, MANIP-02, and MANIP-03.
- Positive (adversarial) and Negative (benign control) test cases.
- Expected versus Actual output comparison with genuine PASS/FAIL verdicts.
- Mathematically rigorous 2x2 confusion matrix (TP, FN, TN, FP).
- Dynamic Precision, Recall, F1-Score, Accuracy, and Leakage Rate calculations.
- Dynamic Category-wise Radar Chart driven by actual test execution outcomes.
- Real wall-clock latency measurement (time.perf_counter()).
- Streamlit session-state execution history with JSON and CSV downloads.

CRITICAL REQUIREMENT: Never claim simulated tests are actual security results.
All metrics, tests, and attack simulations are strictly synthetic benchmarks.
"""

import json
import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from evaluation.test_cases import (
    SYNTHETIC_TEST_SUITE,
    get_manipulation_test_cases,
    get_leakage_test_cases,
    get_categories,
    get_test_cases_by_category
)
from evaluation.metrics import (
    execute_security_test,
    compute_confusion_matrix,
    compute_category_resilience,
    run_synthetic_evaluation
)


def init_session_state():
    """Initialize session state storage for test execution history and results."""
    if "manip_results" not in st.session_state:
        st.session_state["manip_results"] = {}
        for tc in get_manipulation_test_cases():
            res = execute_security_test(tc)
            st.session_state["manip_results"][tc["id"]] = res

    if "leak_results" not in st.session_state:
        st.session_state["leak_results"] = {}
        for tc in get_leakage_test_cases():
            res = execute_security_test(tc)
            st.session_state["leak_results"][tc["id"]] = res

    if "security_execution_history" not in st.session_state:
        st.session_state["security_execution_history"] = []
        for r in st.session_state["manip_results"].values():
            st.session_state["security_execution_history"].append(r)
        for r in st.session_state["leak_results"].values():
            st.session_state["security_execution_history"].append(r)


def render_test_card(tc, results_dict, session_key_prefix):
    """Render a standardized security test card with Expected vs Actual comparison."""
    test_id = tc["id"]
    current_result = results_dict.get(test_id)

    # Determine badge styling for positive vs negative
    is_positive = (tc.get("test_type") == "POSITIVE_ATTACK")
    badge_type = "🔴 POSITIVE ATTACK" if is_positive else "🟢 BENIGN CONTROL"
    badge_style = "tag-sensitive" if is_positive else "tag-verified"

    with st.expander(f"Test {tc['id']}: {tc['name']} ({tc.get('severity', 'MEDIUM')})", expanded=True):
        st.markdown(
            f"<div style='margin-bottom:8px;'>"
            f"<span class='cyber-tag {badge_style}'>{badge_type}</span> "
            f"<span class='cyber-tag tag-verified'>Defense: {tc.get('target_defense', 'Gateway Filter')}</span>"
            f"</div>",
            unsafe_allow_html=True
        )

        st.caption(tc.get("description", ""))

        # Editable input probe
        input_key = f"input_{session_key_prefix}_{test_id}"
        prompt_val = st.text_area(
            "Attack Input Probe (Editable for live evaluation):",
            value=tc.get("input_prompt", ""),
            height=80,
            key=input_key
        )

        # Execution trigger
        col_btn, col_info = st.columns([1.5, 4])
        with col_btn:
            if st.button(f"▶️ Run Test ({test_id})", key=f"btn_{session_key_prefix}_{test_id}", type="secondary"):
                res = execute_security_test(tc, custom_input=prompt_val)
                results_dict[test_id] = res
                st.session_state["security_execution_history"].append(res)
                st.rerun()

        with col_info:
            if current_result:
                st.markdown(
                    f"<div style='font-size:0.82rem; color:#a0aec0; line-height:2.4;'>"
                    f"Last Executed: <strong>{current_result['timestamp']}</strong> | Measured Latency: <strong>{current_result['elapsed_ms']} ms</strong>"
                    f"</div>",
                    unsafe_allow_html=True
                )

        # Expected vs Actual Output Comparison
        if current_result:
            st.markdown("---")
            col_exp, col_act = st.columns(2)

            with col_exp:
                st.markdown("##### 🎯 Expected Behavior")
                st.markdown(f"<div style='font-size:0.85rem; color:#a0aec0; margin-bottom:6px;'>{tc.get('expected_behavior', '')}</div>", unsafe_allow_html=True)
                st.markdown(f"**Expected Wire Substring:** `{tc.get('expected_wire_pattern', 'N/A')}`")

            with col_act:
                st.markdown("##### 🛡️ Actual Sanitized Wire Output")
                st.markdown(f"<div class='wire-payload-box'>{current_result['actual_output']}</div>", unsafe_allow_html=True)
                
                # Verdict Badge
                verdict = current_result['verdict']
                if "PASS" in verdict:
                    verdict_html = f"<span class='cyber-tag tag-redacted' style='font-size:0.88rem; padding:4px 10px;'>✅ {verdict}</span>"
                else:
                    verdict_html = f"<span class='cyber-tag tag-sensitive' style='font-size:0.88rem; padding:4px 10px;'>❌ {verdict}</span>"

                st.markdown(f"<div style='margin-top:8px;'><strong>Verdict:</strong> {verdict_html}</div>", unsafe_allow_html=True)

            # Technical explanation & rules triggered
            st.markdown(f"""
                <div style="background:#091528; border-left:3px solid #00f5d4; padding:8px 12px; border-radius:4px; margin-top:10px; font-size:0.82rem; color:#cbd5e1;">
                    <strong>Evaluation Details:</strong> {current_result['status_detail']}<br>
                    <strong>Security Engine Rules Fired:</strong> {', '.join(current_result['detected_rules']) if current_result['detected_rules'] else 'None (Clean Passthrough)'}
                </div>
            """, unsafe_allow_html=True)


def format_pct(val):
    """Format float percentage or return 'N/A' if undefined."""
    if val is None:
        return "N/A"
    return f"{val:.1f}%"


def render():
    init_session_state()

    # Page Header
    st.markdown("""
        <div class="phasora-header">
            <h2 class="phasora-title">
                🧪 Security Testing Lab
                <span class="badge-pill">ADVERSARIAL RED-TEAMING</span>
            </h2>
            <p class="phasora-subtitle">
                Deterministic rule-based security evaluation engine testing placeholder manipulation, PII leakage, and evasion vectors.
            </p>
        </div>
    """, unsafe_allow_html=True)

    # Mandatory Simulation Notice Banner
    st.markdown("""
        <div class="simulation-banner">
            ⚠️ <strong>SIMULATION NOTICE:</strong> The security evaluation engine runs deterministic rule-based heuristics against synthetic test vectors for pre-deployment benchmarking. These tests represent simulated laboratory evaluations and are NOT certified production security guarantees.
        </div>
    """, unsafe_allow_html=True)

    # Gather active executed test results across manipulation & leakage suites
    active_manip = list(st.session_state["manip_results"].values())
    active_leak = list(st.session_state["leak_results"].values())
    combined_active = active_manip + active_leak

    # Dynamically compute confusion matrix and category resilience
    cm = compute_confusion_matrix(combined_active)
    cat_res = compute_category_resilience(combined_active)

    total_runs = cm["total_executed"]
    passed_runs = cm["tp"] + cm["tn"]
    accuracy_display = format_pct(cm["accuracy"])
    avg_latency = round(sum(r.get("elapsed_ms", 0.0) for r in combined_active) / total_runs, 3) if total_runs > 0 else 0.0

    # Real-Time Lab Summary Metrics Cards
    k1, k2, k3, k4 = st.columns(4)
    with k1:
        st.markdown(f"""
            <div class="cyber-card">
                <div class="cyber-metric-value">{total_runs}</div>
                <div class="cyber-metric-label">Active Security Probes</div>
            </div>
        """, unsafe_allow_html=True)
    with k2:
        st.markdown(f"""
            <div class="cyber-card">
                <div class="cyber-metric-value" style="color:#00f5d4;">{passed_runs} / {total_runs}</div>
                <div class="cyber-metric-label">Passed Defense Checks</div>
            </div>
        """, unsafe_allow_html=True)
    with k3:
        st.markdown(f"""
            <div class="cyber-card">
                <div class="cyber-metric-value">{accuracy_display}</div>
                <div class="cyber-metric-label">Dynamic Accuracy Rate</div>
            </div>
        """, unsafe_allow_html=True)
    with k4:
        st.markdown(f"""
            <div class="cyber-card">
                <div class="cyber-metric-value">{avg_latency} ms</div>
                <div class="cyber-metric-label">Mean Engine Latency</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("###")

    tab_manip, tab_leak, tab_bench, tab_history, tab_suite = st.tabs([
        "🔏 Placeholder Manipulation Tests",
        "🛡️ Sample PII Leakage Tests",
        "📊 Benchmark Scorecard",
        "📜 Execution History & Reports",
        "📋 Synthetic Test Vectors"
    ])

    # -------------------------------------------------------------
    # TAB 1: Placeholder Manipulation Tests (MANIP-01..03 + Negatives)
    # -------------------------------------------------------------
    with tab_manip:
        st.markdown("#### 🔏 Placeholder & Vault Manipulation Tests")
        st.caption("Verify defenses against token vault extraction, prompt injection overrides, and Base64 payload smuggling.")

        col_run_all_m, col_spacer_m = st.columns([2, 3])
        with col_run_all_m:
            if st.button("🚀 Execute All Manipulation Tests", type="primary", key="btn_run_all_manip"):
                for tc in get_manipulation_test_cases():
                    res = execute_security_test(tc)
                    st.session_state["manip_results"][tc["id"]] = res
                    st.session_state["security_execution_history"].append(res)
                st.success("All manipulation test cases executed against rule engine!")
                st.rerun()

        st.markdown("###")
        for tc in get_manipulation_test_cases():
            render_test_card(tc, st.session_state["manip_results"], "manip")

    # -------------------------------------------------------------
    # TAB 2: Sample PII Leakage Tests (LEAK-01..03 + Negatives)
    # -------------------------------------------------------------
    with tab_leak:
        st.markdown("#### 🛡️ Sample PII Leakage Tests")
        st.caption("Test gateway interception of national government IDs, delimiter-spaced digits, and demographic quasi-identifier triads.")

        col_run_all_l, col_spacer_l = st.columns([2, 3])
        with col_run_all_l:
            if st.button("🚀 Execute All Leakage Tests", type="primary", key="btn_run_all_leak"):
                for tc in get_leakage_test_cases():
                    res = execute_security_test(tc)
                    st.session_state["leak_results"][tc["id"]] = res
                    st.session_state["security_execution_history"].append(res)
                st.success("All leakage test cases executed against rule engine!")
                st.rerun()

        st.markdown("###")
        for tc in get_leakage_test_cases():
            render_test_card(tc, st.session_state["leak_results"], "leak")

    # -------------------------------------------------------------
    # TAB 3: Benchmark Scorecard & Dynamically Derived Confusion Matrix
    # -------------------------------------------------------------
    with tab_bench:
        st.markdown("#### 🏆 Benchmark Scorecard & Derived Metrics")
        st.caption("Dynamic security metrics and confusion matrix calculated strictly from executed test runs.")

        # Batch Run Button for Complete Benchmark
        col_run_bench, col_bench_info = st.columns([2, 3])
        with col_run_bench:
            if st.button("▶️ Execute Full Benchmark Suite", type="primary", key="btn_eval_suite"):
                for tc in get_manipulation_test_cases():
                    res = execute_security_test(tc)
                    st.session_state["manip_results"][tc["id"]] = res
                    st.session_state["security_execution_history"].append(res)
                for tc in get_leakage_test_cases():
                    res = execute_security_test(tc)
                    st.session_state["leak_results"][tc["id"]] = res
                    st.session_state["security_execution_history"].append(res)
                st.rerun()

        with col_bench_info:
            st.markdown(
                f"<div style='font-size:0.85rem; color:#a0aec0; line-height:2.3;'>"
                f"Evaluated Probes: <strong>{cm['total_executed']}</strong> (Attacks: <strong>{cm['total_attacks']}</strong> | Controls: <strong>{cm['total_benign']}</strong>)"
                f"</div>",
                unsafe_allow_html=True
            )

        # Dynamic KPI Cards (No hardcoded values)
        st.markdown("###")
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.markdown(f"""
                <div class="cyber-card">
                    <div class="cyber-metric-value">{cm['total_executed']}</div>
                    <div class="cyber-metric-label">Executed Probes</div>
                </div>
            """, unsafe_allow_html=True)
        with c2:
            st.markdown(f"""
                <div class="cyber-card">
                    <div class="cyber-metric-value">{format_pct(cm['precision'])}</div>
                    <div class="cyber-metric-label">Precision (TP / TP+FP)</div>
                </div>
            """, unsafe_allow_html=True)
        with c3:
            st.markdown(f"""
                <div class="cyber-card">
                    <div class="cyber-metric-value">{format_pct(cm['recall'])}</div>
                    <div class="cyber-metric-label">Recall (TP / TP+FN)</div>
                </div>
            """, unsafe_allow_html=True)
        with c4:
            st.markdown(f"""
                <div class="cyber-card">
                    <div class="cyber-metric-value">{format_pct(cm['f1_score'])}</div>
                    <div class="cyber-metric-label">F1 Score</div>
                </div>
            """, unsafe_allow_html=True)
        with c5:
            st.markdown(f"""
                <div class="cyber-card">
                    <div class="cyber-metric-value">{format_pct(cm['leakage_rate'])}</div>
                    <div class="cyber-metric-label">Leakage Rate (FN / Attacks)</div>
                </div>
            """, unsafe_allow_html=True)

        st.markdown("###")

        # ---------------------------------------------------------
        # 2x2 CONFUSION MATRIX VISUALIZATION
        # ---------------------------------------------------------
        st.markdown("#### 🧩 Mathematically Derived 2x2 Confusion Matrix")
        st.caption("Ground truth labels versus gateway interception decisions across all executed positive attacks and negative benign controls.")

        cm_html = f"""
        <div style="background:#091528; border:1px solid #1e3a5f; border-radius:8px; padding:18px; margin-bottom:24px;">
            <table style="width:100%; border-collapse:separate; border-spacing:8px; text-align:center;">
                <thead>
                    <tr>
                        <th style="width:28%; padding:10px; color:#a0aec0; font-size:0.85rem; text-align:left;">
                            GROUND TRUTH \\ DECISION
                        </th>
                        <th style="width:36%; padding:10px; color:#00f5d4; font-size:0.88rem; background:#0d1d36; border-radius:6px;">
                            🛡️ GATEWAY BLOCKED / SANITIZED<br><span style="font-size:0.75rem; color:#a0aec0;">(Predicted Attack)</span>
                        </th>
                        <th style="width:36%; padding:10px; color:#48cae4; font-size:0.88rem; background:#0d1d36; border-radius:6px;">
                            ✅ CLEAN PASSTHROUGH<br><span style="font-size:0.75rem; color:#a0aec0;">(Predicted Benign)</span>
                        </th>
                    </tr>
                </thead>
                <tbody>
                    <tr>
                        <td style="padding:14px; font-weight:700; color:#f0f6fc; text-align:left; background:#0d1d36; border-radius:6px;">
                            🔴 MALICIOUS PROBES<br>
                            <span style="font-size:0.75rem; color:#a0aec0; font-weight:400;">(Positive Attacks: {cm['total_attacks']})</span>
                        </td>
                        <td style="padding:16px; background:rgba(0, 245, 212, 0.12); border:2px solid #00f5d4; border-radius:8px;">
                            <div style="font-size:2rem; font-weight:800; color:#00f5d4; line-height:1.1;">{cm['tp']}</div>
                            <div style="font-size:0.82rem; font-weight:700; color:#ffffff; margin-top:4px;">TRUE POSITIVE (TP)</div>
                            <div style="font-size:0.74rem; color:#a0aec0;">Malicious attack correctly neutralized</div>
                        </td>
                        <td style="padding:16px; background:rgba(255, 92, 119, 0.12); border:2px solid {'#ff5c77' if cm['fn'] > 0 else '#1e3a5f'}; border-radius:8px;">
                            <div style="font-size:2rem; font-weight:800; color:{'#ff5c77' if cm['fn'] > 0 else '#a0aec0'}; line-height:1.1;">{cm['fn']}</div>
                            <div style="font-size:0.82rem; font-weight:700; color:#ffffff; margin-top:4px;">FALSE NEGATIVE (FN)</div>
                            <div style="font-size:0.74rem; color:#a0aec0;">Malicious attack leaked unredacted</div>
                        </td>
                    </tr>
                    <tr>
                        <td style="padding:14px; font-weight:700; color:#f0f6fc; text-align:left; background:#0d1d36; border-radius:6px;">
                            🟢 BENIGN PROBES<br>
                            <span style="font-size:0.75rem; color:#a0aec0; font-weight:400;">(Negative Controls: {cm['total_benign']})</span>
                        </td>
                        <td style="padding:16px; background:rgba(255, 209, 102, 0.12); border:2px solid {'#ffd166' if cm['fp'] > 0 else '#1e3a5f'}; border-radius:8px;">
                            <div style="font-size:2rem; font-weight:800; color:{'#ffd166' if cm['fp'] > 0 else '#a0aec0'}; line-height:1.1;">{cm['fp']}</div>
                            <div style="font-size:0.82rem; font-weight:700; color:#ffffff; margin-top:4px;">FALSE POSITIVE (FP)</div>
                            <div style="font-size:0.74rem; color:#a0aec0;">Benign query falsely blocked (Over-defense)</div>
                        </td>
                        <td style="padding:16px; background:rgba(0, 180, 216, 0.12); border:2px solid #00b4d8; border-radius:8px;">
                            <div style="font-size:2rem; font-weight:800; color:#48cae4; line-height:1.1;">{cm['tn']}</div>
                            <div style="font-size:0.82rem; font-weight:700; color:#ffffff; margin-top:4px;">TRUE NEGATIVE (TN)</div>
                            <div style="font-size:0.74rem; color:#a0aec0;">Benign query correctly allowed without alarm</div>
                        </td>
                    </tr>
                </tbody>
            </table>
            <div style="display:flex; justify-content:space-between; align-items:center; font-size:0.78rem; color:#718096; margin-top:12px; padding:0 6px;">
                <span>• Precision Formula: TP / (TP + FP)</span>
                <span>• Recall Formula: TP / (TP + FN)</span>
                <span>• F1 Formula: 2 * (P * R) / (P + R)</span>
                <span>• Accuracy: (TP + TN) / Total</span>
            </div>
        </div>
        """
        st.markdown(cm_html, unsafe_allow_html=True)

        st.markdown("###")
        col_rad, col_bar = st.columns([1.2, 1])

        with col_rad:
            # DYNAMIC RADAR CHART (Driven exclusively by actual execution data)
            fig_radar = go.Figure()
            fig_radar.add_trace(go.Scatterpolar(
                r=cat_res["scores"],
                theta=cat_res["categories"],
                fill='toself',
                fillcolor='rgba(0, 245, 212, 0.25)',
                line=dict(color='#00f5d4', width=2),
                name='Dynamic Defense Rate'
            ))
            fig_radar.update_layout(
                polar=dict(
                    radialaxis=dict(visible=True, range=[0, 100], color="#a0aec0", gridcolor="#1e3a5f"),
                    angularaxis=dict(color="#f0f6fc", gridcolor="#1e3a5f")
                ),
                showlegend=False,
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                title=dict(text="<b>Dynamic Category Defense Success (%)</b>", font=dict(color="#f0f6fc", size=14)),
                margin=dict(l=40, r=40, t=40, b=40)
            )
            st.plotly_chart(fig_radar, use_container_width=True)

        with col_bar:
            # Latency Bar Chart derived from real test executions
            df_active_lat = pd.DataFrame([
                {"Test ID": r["test_id"], "Measured Latency (ms)": r["elapsed_ms"]}
                for r in combined_active
            ])
            fig_lat = px.bar(
                df_active_lat,
                x="Test ID",
                y="Measured Latency (ms)",
                color="Measured Latency (ms)",
                color_continuous_scale=["#00b4d8", "#00f5d4"],
                title="<b>Measured Latency per Active Probe (ms)</b>"
            )
            fig_lat.update_layout(
                paper_bgcolor='rgba(0,0,0,0)',
                plot_bgcolor='rgba(0,0,0,0)',
                font=dict(color="#f0f6fc"),
                xaxis=dict(gridcolor="#1e3a5f"),
                yaxis=dict(gridcolor="#1e3a5f", title="Latency (ms)"),
                margin=dict(l=20, r=20, t=40, b=20),
                coloraxis_showscale=False
            )
            st.plotly_chart(fig_lat, use_container_width=True)

        # Active Test Execution Breakdown Table
        st.markdown("#### 📋 Active Test Execution Breakdown")
        df_active_table = pd.DataFrame([
            {
                "Test ID": r["test_id"],
                "Test Name": r["test_name"],
                "Category": r["category"],
                "Type": r["test_type"],
                "Latency (ms)": r["elapsed_ms"],
                "Verdict": r["verdict"],
                "Status": "PASS" if r["is_pass"] else "FAIL"
            }
            for r in combined_active
        ])
        st.dataframe(df_active_table, use_container_width=True, hide_index=True)

    # -------------------------------------------------------------
    # TAB 4: Execution History & Report Downloads
    # -------------------------------------------------------------
    with tab_history:
        st.markdown("#### 📜 Persistent Test Execution History & Reports")
        st.caption("Review chronological audit trail of all security tests executed in this session and export reports.")

        history_list = st.session_state.get("security_execution_history", [])

        if history_list:
            df_history = pd.DataFrame(history_list)[[
                "timestamp", "test_id", "test_name", "category", "test_type", "verdict", "elapsed_ms"
            ]]
            df_history.columns = [
                "Timestamp (UTC)", "Test ID", "Test Name", "Category", "Type", "Verdict", "Latency (ms)"
            ]

            st.dataframe(df_history, use_container_width=True, hide_index=True)

            col_json, col_csv, col_clear = st.columns([1.5, 1.5, 1])

            with col_json:
                # Prepare clean JSON report with confusion matrix & execution records
                report_data = {
                    "report_title": "PHASORA Security Testing Lab Execution Report",
                    "generated_at": pd.Timestamp.utcnow().isoformat(),
                    "total_executions": len(history_list),
                    "confusion_matrix": cm,
                    "execution_records": history_list
                }
                json_str = json.dumps(report_data, indent=2)
                st.download_button(
                    label="📥 Download Report (JSON)",
                    data=json_str,
                    file_name="phasora_security_report.json",
                    mime="application/json",
                    use_container_width=True
                )

            with col_csv:
                csv_str = df_history.to_csv(index=False)
                st.download_button(
                    label="📥 Download History (CSV)",
                    data=csv_str,
                    file_name="phasora_security_history.csv",
                    mime="text/csv",
                    use_container_width=True
                )

            with col_clear:
                if st.button("🗑️ Clear History", key="btn_clear_history", use_container_width=True):
                    st.session_state["security_execution_history"] = []
                    st.rerun()
        else:
            st.info("No security tests have been executed yet in this session.")

    # -------------------------------------------------------------
    # TAB 5: Synthetic Test Vectors Explorer
    # -------------------------------------------------------------
    with tab_suite:
        st.markdown("#### 📋 Synthetic Test Suite Explorer")
        st.caption("Review all curated synthetic test vectors designed for evaluating DPDP Act compliance and adversarial robustness.")

        cat_filter = st.selectbox("Filter by Category", ["ALL"] + get_categories())
        if cat_filter == "ALL":
            filtered_cases = SYNTHETIC_TEST_SUITE
        else:
            filtered_cases = get_test_cases_by_category(cat_filter)

        df_cases = pd.DataFrame(filtered_cases)[[
            "id", "category", "subcategory", "dpdp_classification", "is_adversarial", "input_prompt"
        ]]
        df_cases.columns = ["ID", "Category", "Subcategory", "DPDP Classification", "Adversarial", "Synthetic Input Prompt"]
        st.dataframe(df_cases, use_container_width=True, hide_index=True)
