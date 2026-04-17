"""
Network Security Scanner & Firewall Visualizer
Streamlit Frontend - Main Application
"""

import time
import streamlit as st
import pandas as pd
import plotly.graph_objects as go
import plotly.express as px
from scanner import (
    resolve_host, nmap_scan, get_open_ports, get_scan_summary,
    parse_port_range, NMAP_AVAILABLE, PORT_SERVICES
)
from firewall import FirewallSimulator

# ─────────────────────────────────────────────
# Page config
# ─────────────────────────────────────────────
st.set_page_config(
    page_title="NetScan Pro",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded",
)

# ─────────────────────────────────────────────
# Custom CSS — dark cyber aesthetic
# ─────────────────────────────────────────────
st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Rajdhani:wght@400;600;700&display=swap');

html, body, [class*="css"] {
    font-family: 'Rajdhani', sans-serif;
    background-color: #0a0e1a;
    color: #c8d6f0;
}
.stApp {
    background: linear-gradient(135deg, #0a0e1a 0%, #0d1526 50%, #0a1020 100%);
}
h1, h2, h3 { font-family: 'Share Tech Mono', monospace; }

/* Header banner */
.hero-banner {
    background: linear-gradient(90deg, #0d1f3c, #112244, #0d1f3c);
    border: 1px solid #1e3a6e;
    border-left: 4px solid #00d4ff;
    padding: 1.5rem 2rem;
    margin-bottom: 1.5rem;
    border-radius: 4px;
}
.hero-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2rem;
    color: #00d4ff;
    text-shadow: 0 0 20px rgba(0,212,255,0.4);
    margin: 0;
}
.hero-sub {
    color: #6a8ab8;
    margin: 0.2rem 0 0 0;
    font-size: 1rem;
}

/* Metric cards */
.metric-card {
    background: linear-gradient(135deg, #0d1a2e, #112035);
    border: 1px solid #1e3a6e;
    border-top: 3px solid #00d4ff;
    padding: 1rem;
    border-radius: 4px;
    text-align: center;
}
.metric-value { font-family: 'Share Tech Mono', monospace; font-size: 2.2rem; color: #00d4ff; }
.metric-label { color: #6a8ab8; font-size: 0.85rem; text-transform: uppercase; letter-spacing: 1px; }
.metric-card.danger .metric-value { color: #ff4444; }
.metric-card.warn .metric-value { color: #ffaa00; }
.metric-card.safe .metric-value { color: #00ff88; }

/* Status badge */
.badge-open { background:#0d2a1a; color:#00ff88; border:1px solid #00ff88; 
              padding:2px 8px; border-radius:3px; font-size:0.8rem; font-family:monospace;}
.badge-closed { background:#1a0d0d; color:#ff4444; border:1px solid #ff4444;
                padding:2px 8px; border-radius:3px; font-size:0.8rem; font-family:monospace;}
.badge-allow { background:#0d2a1a; color:#00ff88; border:1px solid #00ff88;
               padding:2px 8px; border-radius:3px; font-size:0.8rem; }
.badge-deny  { background:#2a0d0d; color:#ff4444; border:1px solid #ff4444;
               padding:2px 8px; border-radius:3px; font-size:0.8rem; }

/* Section header */
.section-header {
    font-family: 'Share Tech Mono', monospace;
    color: #00d4ff;
    border-bottom: 1px solid #1e3a6e;
    padding-bottom: 0.4rem;
    margin: 1.5rem 0 1rem 0;
    font-size: 1.1rem;
    letter-spacing: 2px;
}

/* Sidebar */
[data-testid="stSidebar"] {
    background: linear-gradient(180deg, #08111f 0%, #0a1525 100%);
    border-right: 1px solid #1e3a6e;
}
[data-testid="stSidebar"] h2 {
    color: #00d4ff;
    font-family: 'Share Tech Mono', monospace;
    font-size: 1rem;
}

/* Buttons */
.stButton > button {
    background: linear-gradient(135deg, #0d3060, #1a4a8a);
    color: #00d4ff;
    border: 1px solid #00d4ff;
    font-family: 'Share Tech Mono', monospace;
    font-weight: bold;
    letter-spacing: 1px;
    transition: all 0.2s;
}
.stButton > button:hover {
    background: linear-gradient(135deg, #1a4a8a, #2060b0);
    box-shadow: 0 0 12px rgba(0,212,255,0.4);
}

/* Info/warning boxes */
.info-box {
    background: #0d1a2e;
    border-left: 3px solid #00d4ff;
    padding: 0.8rem 1rem;
    border-radius: 2px;
    font-size: 0.9rem;
    margin: 0.5rem 0;
}
.warn-box {
    background: #1a1200;
    border-left: 3px solid #ffaa00;
    padding: 0.8rem 1rem;
    border-radius: 2px;
    font-size: 0.9rem;
}

div[data-testid="stDataFrameContainer"] { border: 1px solid #1e3a6e; border-radius: 4px; }
</style>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# Session state initialization
# ─────────────────────────────────────────────
if "firewall" not in st.session_state:
    st.session_state.firewall = FirewallSimulator()
if "scan_results" not in st.session_state:
    st.session_state.scan_results = []
if "scan_summary" not in st.session_state:
    st.session_state.scan_summary = None
if "fw_simulation" not in st.session_state:
    st.session_state.fw_simulation = []
if "last_host" not in st.session_state:
    st.session_state.last_host = ""

fw: FirewallSimulator = st.session_state.firewall

# ─────────────────────────────────────────────
# Hero Header
# ─────────────────────────────────────────────
st.markdown("""
<div class="hero-banner">
  <p class="hero-title">🛡️ NETSCAN PRO</p>
  <p class="hero-sub">Network Security Scanner &amp; Firewall Visualizer</p>
</div>
""", unsafe_allow_html=True)

# ─────────────────────────────────────────────
# Sidebar – Scan Configuration
# ─────────────────────────────────────────────
with st.sidebar:
    st.markdown("## ⚙️ SCAN CONFIG")
    st.divider()

    target = st.text_input("🎯 Target IP / Hostname", value="127.0.0.1",
                           placeholder="e.g. 192.168.1.1 or scanme.nmap.org")

    scan_type = st.selectbox("🔍 Scan Type", [
        "tcp_connect",
        "tcp_syn",
        "udp",
        "comprehensive",
    ], format_func=lambda x: {
        "tcp_connect": "TCP Full Connect",
        "tcp_syn":     "TCP SYN (requires root)",
        "udp":         "UDP Scan",
        "comprehensive": "Comprehensive (SYN+Version)",
    }[x])

    port_preset = st.selectbox("📋 Port Range Preset", [
        "common", "top100", "full", "custom"
    ], format_func=lambda x: {
        "common": "Common Ports (top ~30)",
        "top100": "Top 100 Ports",
        "full":   "Well-Known (1–1024)",
        "custom": "Custom Range",
    }[x])

    port_presets = {
        "common": "21,22,23,25,53,80,110,135,139,143,443,445,587,993,995,1433,3306,3389,5432,5900,6379,8080,8443,27017",
        "top100": "1-100,110,135,139,143,161,389,443,445,587,636,993,995,1433,1521,1723,3306,3389,5432,5900,6379,8080,8443,9200,27017",
        "full":   "1-1024",
    }

    if port_preset == "custom":
        port_range = st.text_input("Port Range", value="80,443,22,3306",
                                   help="e.g. 1-1024 or 80,443,8080")
    else:
        port_range = port_presets[port_preset]
        st.code(f"Ports: {port_range[:60]}{'...' if len(port_range)>60 else ''}", language=None)

    timeout = st.slider("⏱️ Timeout (s)", 0.3, 3.0, 1.0, 0.1)

    st.divider()
    if not NMAP_AVAILABLE:
        st.markdown('<div class="warn-box">⚠️ <b>nmap not installed</b><br>Running in <b>Python TCP fallback mode</b>.<br>All scans use TCP Connect — no root needed.<br><br>To unlock full scan modes, install nmap:<br><code>winget install nmap</code> (Windows)<br><code>brew install nmap</code> (macOS)<br><code>sudo apt install nmap</code> (Linux)</div>', unsafe_allow_html=True)
    else:
        st.markdown('<div class="info-box">✅ nmap detected — full scan capability available</div>', unsafe_allow_html=True)

    st.divider()
    scan_btn = st.button("🚀 START SCAN", use_container_width=True, type="primary")

# ─────────────────────────────────────────────
# TABS
# ─────────────────────────────────────────────
tab1, tab2, tab3, tab4 = st.tabs([
    "📡 Scanner", "🔥 Firewall Rules", "📊 Visualization", "📖 How It Works"
])

# ═══════════════════════════════════════════════
# TAB 1 — Scanner
# ═══════════════════════════════════════════════
with tab1:
    if scan_btn:
        if not target.strip():
            st.error("Please enter a target IP or hostname.")
        else:
            resolved_ip = resolve_host(target.strip())
            if not resolved_ip:
                st.error(f"Could not resolve hostname: `{target}`")
            else:
                st.session_state.last_host = resolved_ip
                progress_bar = st.progress(0, text="Initializing scan...")
                status_text = st.empty()

                with st.spinner(f"Scanning `{resolved_ip}`..."):
                    progress_bar.progress(20, text=f"Resolved: {resolved_ip} — Starting scan...")
                    t_start = time.time()

                    results = nmap_scan(resolved_ip, scan_type, port_range, timeout=timeout)
                    progress_bar.progress(70, text="Parsing results...")
                    duration = time.time() - t_start
                    summary = get_scan_summary(results, resolved_ip, scan_type, duration)

                    st.session_state.scan_results = results
                    st.session_state.scan_summary = summary

                    # Auto-run firewall simulation
                    progress_bar.progress(90, text="Running firewall simulation...")
                    st.session_state.fw_simulation = fw.simulate_scan_results(results, resolved_ip)

                    progress_bar.progress(100, text="Done!")
                    time.sleep(0.3)
                    progress_bar.empty()
                    status_text.success(f"✅ Scan complete in {duration:.2f}s")

    # ── Results display
    if st.session_state.scan_summary:
        s = st.session_state.scan_summary
        results = st.session_state.scan_results

        # Metric row
        c1, c2, c3, c4, c5 = st.columns(5)
        with c1:
            st.markdown(f'<div class="metric-card"><div class="metric-value">{s["total_scanned"]}</div><div class="metric-label">Ports Scanned</div></div>', unsafe_allow_html=True)
        with c2:
            cls = "safe" if s["open_count"] < 5 else "warn" if s["open_count"] < 15 else "danger"
            st.markdown(f'<div class="metric-card {cls}"><div class="metric-value">{s["open_count"]}</div><div class="metric-label">Open Ports</div></div>', unsafe_allow_html=True)
        with c3:
            st.markdown(f'<div class="metric-card"><div class="metric-value">{s["closed_count"]}</div><div class="metric-label">Closed/Filtered</div></div>', unsafe_allow_html=True)
        with c4:
            cls2 = "safe" if s["risky_count"] == 0 else "warn" if s["risky_count"] < 3 else "danger"
            st.markdown(f'<div class="metric-card {cls2}"><div class="metric-value">{s["risky_count"]}</div><div class="metric-label">High-Risk Ports</div></div>', unsafe_allow_html=True)
        with c5:
            st.markdown(f'<div class="metric-card"><div class="metric-value">{s["duration"]}s</div><div class="metric-label">Scan Time</div></div>', unsafe_allow_html=True)

        st.markdown("")

        # Host info
        col_a, col_b = st.columns([3, 1])
        with col_a:
            st.markdown(f'<div class="info-box">🎯 <b>Host:</b> {s["host"]} &nbsp;|&nbsp; 🔍 <b>Scan:</b> {s["scan_type"]} &nbsp;|&nbsp; 🕐 {s["timestamp"]}</div>', unsafe_allow_html=True)

        # Filter
        show_filter = st.radio("Show:", ["All Ports", "Open Only", "With Vulnerabilities"],
                               horizontal=True, label_visibility="collapsed")

        open_only = [r for r in results if r["state"] == "open"]
        vuln_only = [r for r in open_only if r.get("vulnerability")]

        display_map = {
            "All Ports": results,
            "Open Only": open_only,
            "With Vulnerabilities": vuln_only,
        }
        display_data = display_map[show_filter]

        if not display_data:
            st.info("No results to display for the selected filter.")
        else:
            # Build display dataframe
            rows = []
            for r in display_data:
                state_badge = f'<span class="badge-open">OPEN</span>' if r["state"] == "open" else f'<span class="badge-closed">CLOSED</span>'
                rows.append({
                    "Port": r["port"],
                    "Protocol": r["protocol"].upper(),
                    "State": r["state"].upper(),
                    "Service": r["service"],
                    "Vulnerability / Note": r.get("vulnerability", "") or "—",
                })
            df = pd.DataFrame(rows)
            st.dataframe(
                df,
                use_container_width=True,
                hide_index=True,
                column_config={
                    "Port": st.column_config.NumberColumn(width=80),
                    "State": st.column_config.TextColumn(width=90),
                    "Protocol": st.column_config.TextColumn(width=90),
                    "Service": st.column_config.TextColumn(width=140),
                    "Vulnerability / Note": st.column_config.TextColumn(width=420),
                }
            )

    else:
        st.markdown('<div class="info-box" style="text-align:center;padding:2rem;">Configure a target in the sidebar and click <b>START SCAN</b> to begin.</div>', unsafe_allow_html=True)

# ═══════════════════════════════════════════════
# TAB 2 — Firewall Rules
# ═══════════════════════════════════════════════
with tab2:
    col_left, col_right = st.columns([3, 2])

    with col_left:
        st.markdown('<div class="section-header">// ACTIVE RULES</div>', unsafe_allow_html=True)

        rules_data = fw.get_rules_as_dicts()
        if rules_data:
            df_rules = pd.DataFrame(rules_data)
            df_rules = df_rules.rename(columns={
                "rule_id": "ID", "action": "Action", "protocol": "Protocol",
                "src_ip": "Source IP", "dst_ip": "Dest IP",
                "port": "Port", "priority": "Priority", "description": "Description"
            })
            st.dataframe(df_rules, use_container_width=True, hide_index=True)
        else:
            st.info("No rules defined.")

        # Firewall simulation results
        if st.session_state.fw_simulation:
            st.markdown('<div class="section-header">// FIREWALL vs SCAN RESULTS</div>', unsafe_allow_html=True)
            sim_rows = []
            for s in st.session_state.fw_simulation:
                decision = s["firewall_decision"]
                badge = f'<span class="badge-allow">ALLOW</span>' if decision == "ALLOW" else f'<span class="badge-deny">DENY</span>'
                sim_rows.append({
                    "Port": s["port"],
                    "Service": s["service"],
                    "Protocol": s["protocol"],
                    "Decision": decision,
                    "Matched Rule": s["matched_rule"],
                })
            df_sim = pd.DataFrame(sim_rows)
            st.dataframe(df_sim, use_container_width=True, hide_index=True,
                         column_config={
                             "Decision": st.column_config.TextColumn(width=100),
                         })

    with col_right:
        st.markdown('<div class="section-header">// ADD RULE</div>', unsafe_allow_html=True)

        with st.form("add_rule_form"):
            action = st.selectbox("Action", ["ALLOW", "DENY"])
            protocol = st.selectbox("Protocol", ["TCP", "UDP", "ICMP", "ANY"])
            src_ip = st.text_input("Source IP", value="*", help="Use * for any")
            dst_ip = st.text_input("Destination IP", value="*", help="Use * for any")
            port = st.text_input("Port / Range", value="*", help="e.g. 80 or 8000-9000 or *")
            priority = st.number_input("Priority", min_value=1, max_value=999, value=50,
                                       help="Lower = higher priority")
            description = st.text_input("Description (optional)")
            submitted = st.form_submit_button("➕ Add Rule", use_container_width=True)

            if submitted:
                rule = fw.add_rule(action, protocol, src_ip, dst_ip, port, priority, description)
                st.success(f"Rule #{rule.rule_id} added!")
                # Re-run simulation if we have scan results
                if st.session_state.scan_results and st.session_state.last_host:
                    st.session_state.fw_simulation = fw.simulate_scan_results(
                        st.session_state.scan_results, st.session_state.last_host
                    )
                st.rerun()

        st.divider()
        st.markdown('<div class="section-header">// REMOVE RULE</div>', unsafe_allow_html=True)
        col_del1, col_del2 = st.columns([2, 1])
        with col_del1:
            del_id = st.number_input("Rule ID to remove", min_value=1, step=1)
        with col_del2:
            st.markdown("<br>", unsafe_allow_html=True)
            if st.button("🗑️ Remove", use_container_width=True):
                if fw.remove_rule(del_id):
                    st.success(f"Rule #{del_id} removed.")
                    if st.session_state.scan_results and st.session_state.last_host:
                        st.session_state.fw_simulation = fw.simulate_scan_results(
                            st.session_state.scan_results, st.session_state.last_host
                        )
                    st.rerun()
                else:
                    st.error(f"Rule #{del_id} not found.")

        if st.button("🔄 Reset to Defaults", use_container_width=True):
            fw.reset_to_defaults()
            st.session_state.fw_simulation = []
            st.rerun()

        # Packet tester
        st.markdown('<div class="section-header">// PACKET TESTER</div>', unsafe_allow_html=True)
        with st.form("packet_test"):
            pkt_src = st.text_input("Src IP", value="10.0.0.1")
            pkt_dst = st.text_input("Dst IP", value="192.168.1.1")
            pkt_proto = st.selectbox("Protocol", ["TCP", "UDP", "ICMP"])
            pkt_port = st.number_input("Port", min_value=1, max_value=65535, value=80)
            test_btn = st.form_submit_button("🧪 Test Packet")

        if test_btn:
            packet = {"src_ip": pkt_src, "dst_ip": pkt_dst, "protocol": pkt_proto, "port": pkt_port}
            result = fw.evaluate_packet(packet)
            color = "#00ff88" if result["decision"] == "ALLOW" else "#ff4444"
            st.markdown(f"""
            <div style="background:#0d1a2e;border:1px solid {color};border-radius:4px;padding:1rem;margin-top:0.5rem;">
              <div style="font-family:monospace;color:{color};font-size:1.3rem;font-weight:bold;">
                {'✅ ALLOWED' if result['decision']=='ALLOW' else '❌ DENIED'}
              </div>
              <div style="color:#6a8ab8;margin-top:0.4rem;font-size:0.85rem;">
                Matched: <b style="color:#c8d6f0;">Rule #{result['matched_rule_id'] or 'N/A'}</b> — {result['matched_rule_desc']}
              </div>
            </div>
            """, unsafe_allow_html=True)

# ═══════════════════════════════════════════════
# TAB 3 — Visualization
# ═══════════════════════════════════════════════
with tab3:
    results = st.session_state.scan_results
    fw_sim = st.session_state.fw_simulation

    if not results:
        st.markdown('<div class="info-box" style="text-align:center;padding:2rem;">Run a scan first to see visualizations.</div>', unsafe_allow_html=True)
    else:
        open_ports = [r for r in results if r["state"] == "open"]
        closed_ports = [r for r in results if r["state"] != "open"]

        col_v1, col_v2 = st.columns(2)

        # ── Port Status Donut
        with col_v1:
            fig_donut = go.Figure(data=[go.Pie(
                labels=["Open", "Closed/Filtered"],
                values=[len(open_ports), len(closed_ports)],
                hole=0.6,
                marker=dict(colors=["#00ff88", "#2a3a5a"],
                            line=dict(color="#0a0e1a", width=2)),
                textfont=dict(family="Share Tech Mono", color="#c8d6f0"),
            )])
            fig_donut.update_layout(
                title=dict(text="Port Status Distribution", font=dict(color="#00d4ff", family="Share Tech Mono")),
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                font=dict(color="#c8d6f0"),
                legend=dict(font=dict(color="#c8d6f0")),
                showlegend=True,
            )
            st.plotly_chart(fig_donut, use_container_width=True)

        # ── Firewall Allow/Deny Donut
        with col_v2:
            if fw_sim:
                allow_count = sum(1 for s in fw_sim if s["firewall_decision"] == "ALLOW")
                deny_count = sum(1 for s in fw_sim if s["firewall_decision"] == "DENY")
                fig_fw = go.Figure(data=[go.Pie(
                    labels=["ALLOWED", "DENIED"],
                    values=[allow_count, deny_count],
                    hole=0.6,
                    marker=dict(colors=["#00ff88", "#ff4444"],
                                line=dict(color="#0a0e1a", width=2)),
                    textfont=dict(family="Share Tech Mono", color="#c8d6f0"),
                )])
                fig_fw.update_layout(
                    title=dict(text="Firewall Decisions (Open Ports)", font=dict(color="#00d4ff", family="Share Tech Mono")),
                    paper_bgcolor="rgba(0,0,0,0)",
                    plot_bgcolor="rgba(0,0,0,0)",
                    font=dict(color="#c8d6f0"),
                    legend=dict(font=dict(color="#c8d6f0")),
                )
                st.plotly_chart(fig_fw, use_container_width=True)
            else:
                st.info("Run scan with firewall rules to see firewall distribution.")

        # ── Open Ports Bar Chart
        if open_ports:
            st.markdown('<div class="section-header">// OPEN PORT RISK MAP</div>', unsafe_allow_html=True)
            risk_colors = []
            for r in open_ports:
                v = r.get("vulnerability", "")
                if v.startswith("🔴"):
                    risk_colors.append("#ff4444")
                elif v.startswith("⚠️"):
                    risk_colors.append("#ffaa00")
                else:
                    risk_colors.append("#00d4ff")

            fig_bar = go.Figure(data=[go.Bar(
                x=[str(r["port"]) for r in open_ports],
                y=[1] * len(open_ports),
                marker_color=risk_colors,
                text=[r["service"] for r in open_ports],
                textposition="auto",
                hovertemplate="<b>Port %{x}</b><br>Service: %{text}<extra></extra>",
            )])
            fig_bar.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(13,26,46,0.8)",
                font=dict(color="#c8d6f0", family="Rajdhani"),
                xaxis=dict(title="Port Number", color="#6a8ab8", gridcolor="#1e3a6e"),
                yaxis=dict(visible=False),
                showlegend=False,
                height=280,
                annotations=[
                    dict(x=0.01, y=1.12, xref="paper", yref="paper", showarrow=False,
                         text="🔴 Critical  🟡 Warning  🔵 Info", font=dict(color="#6a8ab8", size=12))
                ]
            )
            st.plotly_chart(fig_bar, use_container_width=True)

        # ── Traffic Flow Diagram
        if fw_sim:
            st.markdown('<div class="section-header">// FIREWALL TRAFFIC FLOW</div>', unsafe_allow_html=True)

            allowed = [s for s in fw_sim if s["firewall_decision"] == "ALLOW"]
            denied = [s for s in fw_sim if s["firewall_decision"] == "DENY"]

            nodes = (
                [{"label": "INTERNET", "color": "#00d4ff", "x": 0.05, "y": 0.5}] +
                [{"label": "FIREWALL\nENGINE", "color": "#ffaa00", "x": 0.35, "y": 0.5}] +
                [{"label": f":{s['port']}\n{s['service']}", "color": "#00ff88", "x": 0.75, "y": (i + 1) / (len(allowed) + 1)} for i, s in enumerate(allowed[:6])] +
                [{"label": f":{s['port']}\n{s['service']}", "color": "#ff4444", "x": 0.75, "y": (i + 1) / (len(denied) + 1)} for i, s in enumerate(denied[:6])]
            )

            fig_flow = go.Figure()

            # Draw edges: internet → firewall
            fig_flow.add_shape(type="line", x0=0.1, y0=0.5, x1=0.3, y1=0.5,
                               line=dict(color="#00d4ff", width=2), xref="paper", yref="paper")

            # Draw allowed edges: firewall → allowed services
            for i, s in enumerate(allowed[:6]):
                y = (i + 1) / (len(allowed) + 1)
                fig_flow.add_shape(type="line", x0=0.4, y0=0.5, x1=0.65, y1=y,
                                   line=dict(color="#00ff88", width=1.5, dash="solid"), xref="paper", yref="paper")

            # Draw denied edges
            for i, s in enumerate(denied[:6]):
                y = (i + 1) / (len(denied) + 1)
                fig_flow.add_shape(type="line", x0=0.4, y0=0.5, x1=0.65, y1=y,
                                   line=dict(color="#ff4444", width=1.5, dash="dot"), xref="paper", yref="paper")

            # Draw nodes
            for n in nodes:
                fig_flow.add_annotation(
                    x=n["x"], y=n["y"], xref="paper", yref="paper",
                    text=n["label"],
                    showarrow=False,
                    font=dict(color=n["color"], size=10, family="Share Tech Mono"),
                    bgcolor="#0d1a2e",
                    bordercolor=n["color"],
                    borderwidth=1,
                    borderpad=6,
                )

            fig_flow.update_layout(
                paper_bgcolor="rgba(0,0,0,0)",
                plot_bgcolor="rgba(0,0,0,0)",
                height=350,
                xaxis=dict(visible=False), yaxis=dict(visible=False),
                margin=dict(l=20, r=20, t=20, b=20),
                annotations=fig_flow.layout.annotations,
            )
            st.plotly_chart(fig_flow, use_container_width=True)

# ═══════════════════════════════════════════════
# TAB 4 — How It Works
# ═══════════════════════════════════════════════
with tab4:
    st.markdown("## 📖 How It Works")
    col_h1, col_h2 = st.columns(2)

    with col_h1:
        st.markdown("""
### 🔍 Port Scanning
The scanner sends network packets to target ports and analyzes responses:
- **TCP Connect**: Full 3-way handshake — no root required, most compatible
- **TCP SYN**: Half-open scan — stealthier, requires root privileges
- **UDP**: Sends empty datagrams, detects open UDP services
- **Comprehensive**: SYN scan + service/version detection

**Port States:**
- `OPEN` — Service is listening and accepting connections
- `CLOSED` — Port reached but no service responding
- `FILTERED` — Firewall blocking; no response received

### ⚠️ Vulnerability Hints
Each open port is matched against a database of known risk indicators:
- 🔴 **Critical** — Immediate action recommended (e.g., RDP exposed, Redis no-auth)
- ⚠️ **Warning** — Elevated risk, review recommended (e.g., FTP, MySQL)
- ✅ **Info** — Best practice note (e.g., TLS version check)
        """)

    with col_h2:
        st.markdown("""
### 🔥 Firewall Simulation
Rules are evaluated in **priority order** (lowest number first):
1. Each packet attribute (src IP, dst IP, protocol, port) is checked against the rule
2. The **first matching rule** determines the decision (ALLOW or DENY)
3. If no rule matches → **implicit deny**

**Rule Chaining Example:**
```
Priority 1:  DENY  TCP  *  *  23    → Block Telnet
Priority 10: ALLOW TCP  *  *  80    → Allow HTTP
Priority 999: DENY ANY  *  *  *     → Block everything else
```

### 🧪 Packet Tester
Simulate any custom packet through the rule chain to preview exactly which rule triggers and whether traffic would be allowed or denied — before deploying changes to a real firewall.

### 🔧 Tech Stack
- **Frontend**: Streamlit (Python)
- **Scanner**: python-nmap / Python socket fallback
- **Firewall logic**: Custom Python priority-chain engine
- **Charts**: Plotly
        """)
