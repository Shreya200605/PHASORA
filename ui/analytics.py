"""
PHASORA UI - Privacy Analytics Module
====================================
Interactive visual analytics for enterprise privacy posture, PII distribution,
gateway latency overhead, and regulatory compliance status.

Uses Plotly for interactive visualization and Pandas for dataset aggregation.
All data presented represents simulated enterprise telemetry.
"""

import streamlit as st
import pandas as pd
import numpy as np
import plotly.express as px
import plotly.graph_objects as go
from datetime import datetime, timedelta


def generate_sample_telemetry():
    """Generate realistic synthetic telemetry for analytics dashboard."""
    np.random.seed(42)
    dates = [datetime.now() - timedelta(days=i) for i in range(30, 0, -1)]
    
    daily_requests = [int(np.random.normal(8500, 1200)) for _ in dates]
    entities_shielded = [int(req * np.random.uniform(2.8, 3.6)) for req in daily_requests]
    latencies = [round(float(np.random.normal(14.2, 1.1)), 2) for _ in dates]
    
    df_trend = pd.DataFrame({
        "Date": [d.strftime("%Y-%m-%d") for d in dates],
        "Prompts Guarded": daily_requests,
        "Redactions Count": entities_shielded,
        "Avg Gateway Latency (ms)": latencies,
        "Privacy Utility (%)": [round(float(np.random.uniform(96.2, 98.4)), 2) for _ in dates]
    })
    
    return df_trend


def render():
    st.markdown("""
        <div class="phasora-header">
            <h2 class="phasora-title">
                📊 Privacy Analytics
                <span class="badge-pill">TELEMETRY & METRICS</span>
            </h2>
            <p class="phasora-subtitle">
                Real-time visibility into sensitive data interception, precision/recall metrics, and latency budgets.
            </p>
        </div>
    """, unsafe_allow_html=True)

    # Sample Data Disclaimer
    st.markdown("""
        <div class="simulation-banner">
            ℹ️ <strong>SAMPLE DATA NOTICE:</strong> The telemetry shown below represents synthetic enterprise activity logs for dashboard validation. Live production hooks will stream telemetry from the core privacy backend.
        </div>
    """, unsafe_allow_html=True)

    # Top Control Filters
    f1, f2, f3 = st.columns(3)
    with f1:
        time_range = st.selectbox("Telemetry Window", ["Last 30 Days", "Last 7 Days", "Last 90 Days"])
    with f2:
        department_filter = st.selectbox(
            "Department Filter",
            ["All Departments", "Fintech & Banking", "Digital Health", "HR Operations", "Customer Support"]
        )
    with f3:
        compliance_filter = st.selectbox(
            "Regulatory Baseline",
            ["India DPDP Act 2023", "GDPR (EU)", "HIPAA (Healthcare)", "Combined Global Standard"]
        )

    df_trend = generate_sample_telemetry()
    if time_range == "Last 7 Days":
        df_trend = df_trend.tail(7)

    # Key Performance Indicators (Directly addressing Requirement 8)
    total_prompts = df_trend["Prompts Guarded"].sum()
    total_redactions = df_trend["Redactions Count"].sum()
    avg_latency = round(df_trend["Avg Gateway Latency (ms)"].mean(), 2)
    avg_utility = round(df_trend["Privacy Utility (%)"].mean(), 2)

    st.markdown("#### 🎯 Core Privacy & Gateway Metrics")
    k1, k2, k3, k4, k5 = st.columns(5)
    with k1:
        st.markdown("""
            <div class="cyber-card">
                <div class="cyber-metric-value" style="color: #00f5d4;">99.4%</div>
                <div class="cyber-metric-label">Detection Precision</div>
            </div>
        """, unsafe_allow_html=True)
    with k2:
        st.markdown("""
            <div class="cyber-card">
                <div class="cyber-metric-value" style="color: #00f5d4;">98.8%</div>
                <div class="cyber-metric-label">Detection Recall</div>
            </div>
        """, unsafe_allow_html=True)
    with k3:
        st.markdown(f"""
            <div class="cyber-card">
                <div class="cyber-metric-value">{total_redactions:,}</div>
                <div class="cyber-metric-label">Total Redaction Counts</div>
            </div>
        """, unsafe_allow_html=True)
    with k4:
        st.markdown(f"""
            <div class="cyber-card">
                <div class="cyber-metric-value">{avg_latency} ms</div>
                <div class="cyber-metric-label">Gateway Latency</div>
            </div>
        """, unsafe_allow_html=True)
    with k5:
        st.markdown(f"""
            <div class="cyber-card">
                <div class="cyber-metric-value">{avg_utility}%</div>
                <div class="cyber-metric-label">Privacy Utility Score</div>
            </div>
        """, unsafe_allow_html=True)

    st.markdown("###")

    # Row 1: Trend Charts
    c_trend, c_donut = st.columns([1.6, 1])

    with c_trend:
        fig_trend = go.Figure()
        fig_trend.add_trace(go.Scatter(
            x=df_trend["Date"],
            y=df_trend["Redactions Count"],
            mode='lines+markers',
            name='Redactions Count',
            line=dict(color='#00f5d4', width=2.5),
            fill='tozeroy',
            fillcolor='rgba(0, 245, 212, 0.12)'
        ))
        fig_trend.add_trace(go.Scatter(
            x=df_trend["Date"],
            y=df_trend["Prompts Guarded"],
            mode='lines',
            name='Prompts Guarded',
            line=dict(color='#00b4d8', width=2, dash='dot')
        ))
        fig_trend.update_layout(
            title="<b>Daily Prompts vs Redactions Count Trend</b>",
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#f0f6fc"),
            xaxis=dict(gridcolor="#1e3a5f", showgrid=True),
            yaxis=dict(gridcolor="#1e3a5f", showgrid=True),
            legend=dict(orientation="h", yanchor="bottom", y=1.02, xanchor="right", x=1),
            margin=dict(l=30, r=20, t=50, b=30)
        )
        st.plotly_chart(fig_trend, use_container_width=True)

    with c_donut:
        entity_types = ["Indian Aadhaar", "Indian PAN", "Phone Numbers", "Emails", "Bank Accounts", "Health / ABHA IDs", "Quasi-Demographics"]
        entity_counts = [34200, 28900, 45100, 39800, 22100, 18400, 15300]
        
        fig_donut = px.pie(
            values=entity_counts,
            names=entity_types,
            hole=0.6,
            title="<b>Shielded Entity Distribution</b>",
            color_discrete_sequence=["#00f5d4", "#00b4d8", "#48cae4", "#72efdd", "#5e60ce", "#4ea8de", "#90e0ef"]
        )
        fig_donut.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#f0f6fc"),
            margin=dict(l=20, r=20, t=50, b=20),
            legend=dict(font=dict(size=10))
        )
        st.plotly_chart(fig_donut, use_container_width=True)

    st.markdown("###")

    # Row 2: Gateway Latency Breakdown & Department Distribution
    c_lat, c_dept = st.columns([1, 1.2])

    with c_lat:
        stages = ["PII Regex/Heuristic", "Vault Tokenization", "Adversarial Check", "Client Re-Assembly"]
        stage_times = [4.2, 5.1, 3.8, 1.5]
        
        fig_bar = px.bar(
            x=stages,
            y=stage_times,
            title="<b>Gateway Overhead Breakdown by Stage (ms)</b>",
            color=stage_times,
            color_continuous_scale=["#00b4d8", "#00f5d4"],
            text=stage_times
        )
        fig_bar.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#f0f6fc"),
            xaxis=dict(gridcolor="#1e3a5f", title="Pipeline Stage"),
            yaxis=dict(gridcolor="#1e3a5f", title="Time (ms)"),
            margin=dict(l=20, r=20, t=50, b=20),
            coloraxis_showscale=False
        )
        st.plotly_chart(fig_bar, use_container_width=True)

    with c_dept:
        depts = ["Fintech / Banking", "Customer Support", "People Operations (HR)", "Digital Health", "Legal & Procurement"]
        queries = [112400, 78300, 42100, 31900, 19820]
        
        fig_dept = px.bar(
            x=queries,
            y=depts,
            orientation='h',
            title="<b>Guarded Queries by Enterprise Department</b>",
            color_discrete_sequence=['#00f5d4']
        )
        fig_dept.update_layout(
            paper_bgcolor='rgba(0,0,0,0)',
            plot_bgcolor='rgba(0,0,0,0)',
            font=dict(color="#f0f6fc"),
            xaxis=dict(gridcolor="#1e3a5f", title="Queries Processed"),
            yaxis=dict(gridcolor="#1e3a5f", title=""),
            margin=dict(l=20, r=20, t=50, b=20)
        )
        st.plotly_chart(fig_dept, use_container_width=True)

    # Telemetry Log Preview Table
    st.markdown("#### 📄 Synthetic Gateway Telemetry Table")
    st.dataframe(df_trend, use_container_width=True, hide_index=True)
