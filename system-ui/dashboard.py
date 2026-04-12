import streamlit as st
import pandas as pd
import numpy as np
import joblib
import matplotlib.pyplot as plt
import io
import time


@st.cache_resource
def load_model(path):
    return joblib.load(path)

@st.cache_resource
def load_scaler(path):
    return joblib.load(path)


def score_new_connection(data_source, new_traffic_data):
    try:
        live_data = new_traffic_data.copy()

        live_data.replace([np.inf, -np.inf], np.nan, inplace=True)
        live_data.fillna(0, inplace=True)

        if data_source == 'CIC':
            model = load_model('nids_cic_model.joblib')
            scaler = load_scaler('cic_scaler.joblib')

            for col in ['Timestamp', 'Label']:
                if col in live_data.columns:
                    live_data.drop(columns=col, inplace=True)

            for col in live_data.columns:
                live_data[col] = pd.to_numeric(live_data[col], errors='coerce')

            live_data.fillna(0, inplace=True)

            model_features = model.feature_names_in_
            live_data = live_data.reindex(columns=model_features, fill_value=0)

            live_data = pd.DataFrame(
                scaler.transform(live_data),
                columns=model_features
            )

            processed_data = live_data

        else:  # KDD
            model = load_model('nids_kdd_model.joblib')

            live_data = pd.get_dummies(
                live_data,
                columns=['protocol_type', 'service', 'flag']
            )

            model_features = model.feature_names_in_
            processed_data = live_data.reindex(columns=model_features, fill_value=0)

        processed_data = processed_data.astype(np.float32)
        prediction = model.predict(processed_data)

        return int(prediction[0])

    except Exception as e:
        st.error(f"Error loading model or processing data: {e}")
        return 0



def generate_mock_data(selected_network):
    if selected_network == "CIC":
        model = load_model('nids_cic_model.joblib')
        mock_data = pd.DataFrame(
            np.random.rand(1, len(model.feature_names_in_)),
            columns=model.feature_names_in_
        )
    else:
        mock_data = pd.DataFrame([{
            "duration": np.random.randint(0, 5),
            "protocol_type": np.random.choice(["tcp", "udp", "icmp"]),
            "service": np.random.choice(["http", "ftp", "smtp", "domain_u"]),
            "flag": np.random.choice(["SF", "S0", "REJ"])
        }])
    return mock_data


def get_mitre_name(prediction):
    if prediction == 1:
        return "Suspicious Network Traffic"
    return "Normal Traffic"


def process_packet(selected_network):
    mock_data = generate_mock_data(selected_network)
    prediction = score_new_connection(selected_network, mock_data)

    st.session_state.total_scanned += 1

    timestamp_str = pd.Timestamp.now().strftime("%Y-%m-%d %H:%M:%S")
    timestamp_real = pd.Timestamp.now()

    if prediction == 1:
        st.session_state.total_attacks += 1
        status = "🚨 ATTACK DETECTED"
    else:
        status = "✅ BENIGN"

    mitre_name = get_mitre_name(prediction)

    new_log = pd.DataFrame(
        [[timestamp_str, selected_network, status, mitre_name]],
        columns=["Timestamp", "Network", "Status", "Mitre Name"]
    )

    st.session_state.alert_history = pd.concat(
        [st.session_state.alert_history, new_log],
        ignore_index=True
    )

    new_traffic = pd.DataFrame(
        [[timestamp_real, 1 if prediction == 0 else 0, 1 if prediction == 1 else 0]],
        columns=["Time", "Benign", "Attacks"]
    )

    st.session_state.traffic_over_time = pd.concat(
        [st.session_state.traffic_over_time, new_traffic],
        ignore_index=True
    )


def fig_to_png_download(fig):
    buf = io.BytesIO()
    fig.savefig(buf, format="png", bbox_inches="tight")
    buf.seek(0)
    return buf


def get_threat_level(total_scanned, total_attacks):
    if total_scanned == 0:
        return "LOW", "green"

    attack_ratio = total_attacks / total_scanned

    if attack_ratio > 0.2:
        return "HIGH (CRITICAL)", "red"
    elif attack_ratio > 0.05:
        return "ELEVATED", "orange"
    else:
        return "LOW", "green"



st.set_page_config(page_title="Live NIDS Dashboard", layout="wide")


st.markdown("""
<style>
div.stDownloadButton > button {
    padding: 0.35rem 0.55rem;
    min-height: 32px;
    border-radius: 50%;
    border: 1px solid #cfcfcf;
    background-color: white;
    font-size: 16px;
    line-height: 1;
}
div.stDownloadButton > button:hover {
    border: 1px solid #999999;
    background-color: #f5f5f5;
    color: black;
}
</style>
""", unsafe_allow_html=True)


st.markdown("""
<h1 style='text-align: center;'>Real-Time Network Intrusion Detection System</h1>
<p style='text-align: center; font-size: 18px;'>
Monitoring live network traffic and detecting possible attacks.
</p>
""", unsafe_allow_html=True)


if 'total_scanned' not in st.session_state:
    st.session_state.total_scanned = 0
if 'total_attacks' not in st.session_state:
    st.session_state.total_attacks = 0
if 'alert_history' not in st.session_state:
    st.session_state.alert_history = pd.DataFrame(columns=["Timestamp", "Network", "Status", "Mitre Name"])
if 'traffic_over_time' not in st.session_state:
    st.session_state.traffic_over_time = pd.DataFrame(columns=["Time", "Benign", "Attacks"])
if 'monitoring' not in st.session_state:
    st.session_state.monitoring = False
if 'refresh_rate' not in st.session_state:
    st.session_state.refresh_rate = 2
if 'last_run_time' not in st.session_state:
    st.session_state.last_run_time = 0.0


st.sidebar.header("System Controls")

selected_network = st.sidebar.selectbox(
    "Select Network Architecture to Monitor:",
    ["CIC", "KDD"]
)

st.session_state.refresh_rate = st.sidebar.slider(
    "Live Monitoring Speed (seconds)",
    min_value=1,
    max_value=10,
    value=2
)

col_btn1, col_btn2 = st.sidebar.columns(2)

start_clicked = False
stop_clicked = False

with col_btn1:
    if st.button("▶ Start Monitoring", use_container_width=True):
        start_clicked = True

with col_btn2:
    if st.button("⏹ Stop Monitoring", use_container_width=True):
        stop_clicked = True

if start_clicked:
    st.session_state.monitoring = True
    st.session_state.last_run_time = time.time()
    process_packet(selected_network)

if stop_clicked:
    st.session_state.monitoring = False

manual_simulate = st.sidebar.button("Simulate One Packet", use_container_width=True)

if manual_simulate:
    process_packet(selected_network)


current_time = time.time()

if st.session_state.monitoring:
    st.sidebar.success("Live monitoring is running.")

    if not start_clicked and current_time - st.session_state.last_run_time >= st.session_state.refresh_rate:
        process_packet(selected_network)
        st.session_state.last_run_time = current_time
else:
    st.sidebar.info("Monitoring is stopped.")


threat_level, threat_color = get_threat_level(
    st.session_state.total_scanned,
    st.session_state.total_attacks
)

st.markdown(f"### System Threat Status: :{threat_color}[{threat_level}]")

if threat_level == "HIGH (CRITICAL)":
    st.warning("Critical threat level detected. Immediate attention is needed.")


col1, col2, col3 = st.columns(3)

col1.metric("Live Connection Counter", st.session_state.total_scanned)

attack_ratio = 0
if st.session_state.total_scanned > 0:
    attack_ratio = st.session_state.total_attacks / st.session_state.total_scanned

col2.metric("Attack Ratio", f"{attack_ratio:.2%}")

col3.metric("Active Threats Detected", st.session_state.total_attacks)

st.markdown("---")
st.subheader("Network Traffic Analytics")

chart_col1, chart_col2, chart_col3 = st.columns(3)


with chart_col1:
    title_col, download_col = st.columns([8, 1])
    with title_col:
        st.markdown("#### Traffic Over Time")

    if not st.session_state.traffic_over_time.empty:
        chart_data = st.session_state.traffic_over_time.set_index("Time")
        st.line_chart(chart_data)

        fig1, ax1 = plt.subplots()
        ax1.plot(chart_data.index, chart_data["Benign"], label="Benign")
        ax1.plot(chart_data.index, chart_data["Attacks"], label="Attacks")
        ax1.set_title("Traffic Over Time")
        ax1.set_xlabel("Time")
        ax1.set_ylabel("Connections")
        ax1.legend()
        plt.xticks(rotation=45)

        png1 = fig_to_png_download(fig1)
        with download_col:
            st.download_button(
                label="⬇",
                data=png1,
                file_name="traffic_over_time.png",
                mime="image/png",
                key="download_line_chart",
                help="Download"
            )
        plt.close(fig1)
    else:
        st.info("Awaiting traffic data...")


with chart_col2:
    title_col, download_col = st.columns([8, 1])
    with title_col:
        st.markdown("#### Benign vs Attacks")

    if st.session_state.total_scanned > 0:
        benign_count = st.session_state.total_scanned - st.session_state.total_attacks
        attack_count = st.session_state.total_attacks

        fig2, ax2 = plt.subplots()
        ax2.pie(
            [benign_count, attack_count],
            labels=["Benign", "Attacks"],
            autopct='%1.1f%%'
        )
        ax2.set_title("Traffic Distribution")
        st.pyplot(fig2)

        png2 = fig_to_png_download(fig2)
        with download_col:
            st.download_button(
                label="⬇",
                data=png2,
                file_name="traffic_distribution.png",
                mime="image/png",
                key="download_pie_chart",
                help="Download"
            )
        plt.close(fig2)
    else:
        st.info("Awaiting traffic data...")


with chart_col3:
    title_col, download_col = st.columns([8, 1])
    with title_col:
        st.markdown("#### Network Threat Activity")

    if not st.session_state.alert_history.empty:
        network_counts = st.session_state.alert_history["Network"].value_counts()
        st.bar_chart(network_counts)

        fig3, ax3 = plt.subplots()
        network_counts.plot(kind="bar", ax=ax3)
        ax3.set_title("Detected Events Per Network")
        ax3.set_xlabel("Network")
        ax3.set_ylabel("Count")

        png3 = fig_to_png_download(fig3)
        with download_col:
            st.download_button(
                label="⬇",
                data=png3,
                file_name="detected_events_per_network.png",
                mime="image/png",
                key="download_bar_chart",
                help="Download"
            )
        plt.close(fig3)
    else:
        st.info("Awaiting alert data...")

st.markdown("---")


table_title_col, table_download_col = st.columns([8, 1])
with table_title_col:
    st.subheader("Filterable Alert Table")

filter_option = st.selectbox(
    "Filter Alerts By Status:",
    ["All", "BENIGN", "ATTACK DETECTED"]
)

if not st.session_state.alert_history.empty:
    df = st.session_state.alert_history.copy()

    if filter_option != "All":
        df = df[df["Status"] == filter_option]

    st.dataframe(df, use_container_width=True)

    csv = df.to_csv(index=False).encode("utf-8")
    with table_download_col:
        st.download_button(
            label="⬇",
            data=csv,
            file_name="alert_history.csv",
            mime="text/csv",
            key="download_table_csv",
            help="Download"
        )
else:
    st.info("No activity yet. Start monitoring or simulate traffic to begin.")


if st.session_state.monitoring:
    st.rerun()
