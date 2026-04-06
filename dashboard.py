import streamlit as st
import pandas as pd
import time
import random 
import plotly.express as px


st.set_page_config(page_title="NIDS Live Dashboard", layout="wide")

st.markdown("<h1 style='text-align: center;'>Real-Time Network Intrusion Detection System</h1>", unsafe_allow_html=True)


st.markdown("""
    <style>
    /* Start button (Primary) */
    button[kind="primary"] {
        background-color: #91D06C !important;
        color: black !important; 
        border: none !important;
        transition: 0.3s; 
    }
    button[kind="primary"]:hover {
        background-color: #79AE6F !important; 
        color: black !important;
        transform: scale(1.02);
    }
    
    /* Stop button (Secondary) */
    button[kind="secondary"] {
        background-color: #FF5656 !important; 
        color: white !important; 
        border: none !important;
        transition: 0.3s; 
    }
    button[kind="secondary"]:hover {
        background-color: #E04B4B !important; 
        color: white !important;
        transform: scale(1.02);
    }
    </style>
""", unsafe_allow_html=True)


if 'is_running' not in st.session_state:
    st.session_state.is_running = False
if 'total_connections' not in st.session_state:
    st.session_state.total_connections = 0
if 'alert_log' not in st.session_state:
    
    st.session_state.alert_log = pd.DataFrame(columns=['time', 'attack type', 'mitre id', 'mitre name', 'description'])
if 'traffic_data' not in st.session_state:
    st.session_state.traffic_data = pd.DataFrame(columns=['Timestamp', 'Connections'])


col_btn1, col_btn2, col_btn3 = st.columns(3)
with col_btn2:
    
    sub_col1, sub_col2 = st.columns(2)
    
    with sub_col1:
        if st.button("Start Live Monitoring", type="primary", use_container_width=True):
            st.session_state.is_running = True
            
    with sub_col2:
        if st.button("Stop Live Monitoring", type="secondary", use_container_width=True):
            st.session_state.is_running = False

# DASHBOARD DISPLAY
if st.session_state.is_running or st.session_state.total_connections > 0:

    # Live Counter & Threat Level
    col1, col2, col3 = st.columns(3)
    col1.metric("Live Connection Counter", st.session_state.total_connections)
    
    recent_attacks = len(st.session_state.alert_log)
    threat_level = "🔴 CRITICAL" if recent_attacks > 10 else "🟡 ELEVATED" if recent_attacks > 0 else "🟢 LOW"
    col2.metric("Current Threat Level", threat_level)
    col3.metric("Active Threats Detected", recent_attacks)

    # Charts
    st.subheader("Network Traffic Analytics")
    chart_col1, chart_col2, chart_col3 = st.columns(3)
    
    with chart_col1:
        st.markdown("**Traffic Volume (Line Chart)**")
        if not st.session_state.traffic_data.empty:
            st.line_chart(st.session_state.traffic_data.set_index('Timestamp'))
        else:
            st.info("Waiting for traffic data...")

    with chart_col2:
        st.markdown("**Attack Distribution (Pie Chart)**")
        if not st.session_state.alert_log.empty:
           
            attack_counts = st.session_state.alert_log['attack type'].value_counts().reset_index()
            attack_counts.columns = ['attack type', 'Count']

            fig_pie = px.pie(attack_counts, names='attack type', values='Count', hole=0.4,
                             color_discrete_sequence=px.colors.qualitative.Pastel)
            st.plotly_chart(fig_pie, use_container_width=True)
        else:
            st.success("No attacks detected.")

    with chart_col3:
        st.markdown("**MITRE ATT&CK Techniques (Bar Chart)**")
        if not st.session_state.alert_log.empty:
            
            attack_counts = st.session_state.alert_log.groupby(['attack type', 'mitre id', 'mitre name', 'description']).size().reset_index(name='Count')
            
           
            attack_counts['Technique'] = attack_counts['mitre id'] + " - " + attack_counts['mitre name']
            
            
            fig_bar = px.bar(attack_counts, x='Technique', y='Count', color='attack type',
                             hover_data=['description'], 
                             color_discrete_sequence=px.colors.qualitative.Set3)
            
            
            fig_bar.update_layout(xaxis_title="", showlegend=True)
            st.plotly_chart(fig_bar, use_container_width=True)
        else:
            st.success("Log is clean.")

    # Filterable Alert Table 
    st.subheader("Suspicious Connections (Filterable Alert Table)")
    if not st.session_state.alert_log.empty:
        attack_filter = st.selectbox("Filter by Attack Type", ["All"] + list(st.session_state.alert_log['attack type'].unique()))
        
        
        display_df = st.session_state.alert_log.drop(columns=['description'])
        
        if attack_filter == "All":
            st.dataframe(display_df, use_container_width=True, hide_index=True)
        else:
            filtered_df = display_df[display_df['attack type'] == attack_filter]
            st.dataframe(filtered_df, use_container_width=True, hide_index=True)
    else:
        st.info("Log is clean. No suspicious connections.")

# SIMULATION LOOP 
if st.session_state.is_running:
    time.sleep(1)
    
    current_time = pd.Timestamp.now().strftime("%H:%M:%S")
    st.session_state.total_connections += 1
    
    new_traffic = pd.DataFrame({'Timestamp': [current_time], 'Connections': [random.randint(10, 100)]})
    st.session_state.traffic_data = pd.concat([st.session_state.traffic_data, new_traffic], ignore_index=True)
    
    if len(st.session_state.traffic_data) > 20:
        st.session_state.traffic_data = st.session_state.traffic_data.iloc[-20:]

    if random.random() < 0.2:
        # Expanded dictionary mapping all 9 attacks from your dataset to MITRE ATT&CK
        mitre_mapping = {
            'nmap': {'id': 'T1046', 'name': 'Network Service Discovery', 'desc': 'Scanning for open ports/services listening on remote hosts.'},
            'neptune (SYN Flood)': {'id': 'T1498.001', 'name': 'Direct Network Flood', 'desc': 'Rapid TCP SYN requests to consume server resources.'},
            'satan / portsweep': {'id': 'T1046', 'name': 'Network Service Discovery', 'desc': 'Identifying vulnerable software via port scans.'},
            'ipsweep': {'id': 'T1018', 'name': 'Remote System Discovery', 'desc': 'Sweeping IP addresses to identify active hosts.'},
            'smurf': {'id': 'T1498.002', 'name': 'Reflection Amplification', 'desc': 'Flooding victim with ICMP echo replies via spoofed IP.'},
            'guess_passwd': {'id': 'T1110.001', 'name': 'Password Guessing', 'desc': 'Systematically guessing passwords for unauthorized access.'},
            'rootkit': {'id': 'T1014', 'name': 'Rootkit', 'desc': 'Hiding malicious programs and connections from the OS.'},
            'teardrop': {'id': 'T1499', 'name': 'Endpoint Denial of Service', 'desc': 'Sending fragmented, overlapping IP packets to crash the OS.'},
            'buffer_overflow': {'id': 'T1068', 'name': 'Exploitation for Privilege Escalation', 'desc': 'Overwriting adjacent memory to execute malicious code.'}
        }
        
        selected_attack = random.choice(list(mitre_mapping.keys()))
        attack_info = mitre_mapping[selected_attack]
        
        new_alert = pd.DataFrame({
            'time': [current_time], 
            'attack type': [selected_attack], 
            'mitre id': [attack_info['id']],
            'mitre name': [attack_info['name']],
            'description': [attack_info['desc']]
        })
        st.session_state.alert_log = pd.concat([st.session_state.alert_log, new_alert], ignore_index=True)
    
    st.rerun()