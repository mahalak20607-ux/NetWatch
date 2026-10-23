import streamlit as st

st.set_page_config(
    page_title="NetWatch",
    page_icon="🌐",
    layout="wide"
)

st.title("🌐 NetWatch")
st.subheader("Real-Time Network Traffic Monitoring System")

st.success("Application is running successfully!")

col1, col2, col3 = st.columns(3)

col1.metric("Packets Captured", 120)
col2.metric("Protocols Detected", 4)
col3.metric("Anomaly Alerts", 3)

st.info("Testing the NetWatch dashboard.")

st.line_chart({
    "Network Traffic": [10, 20, 15, 35, 28, 45]
})