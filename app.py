
import streamlit as st
import scapy.all as scapy
import datetime
from collections import Counter
import pandas as pd
import plotly.express as px

# Configure page settings
st.set_page_config(
    page_title="Wireshark Analyzer",
    page_icon="🖧",
    layout="wide"
)

# Page title
st.title("🖧 Wireshark Analyzer")
st.write("Upload a PCAP or PCAPNG file")

# File uploader
uploaded_file = st.file_uploader(
    "Choose PCAP or PCAPNG file",
    type=["pcap", "pcapng"]
)

# Analyze uploaded file
if uploaded_file is not None:

    # Read packets
    try:
        packets = scapy.rdpcap(uploaded_file)
    except Exception as e:
        st.error(f"Error reading capture file: {e}")
        st.stop()

    # Check if capture is empty
    if len(packets) == 0:
        st.warning("The uploaded capture contains no packets.")
        st.stop()

    # Packet statistics
    packet_count = len(packets)

    start_time = float(packets[0].time)
    end_time = float(packets[-1].time)
    duration = end_time - start_time

    # Display capture information
    st.subheader("Capture Information")

    col1, col2, col3, col4 = st.columns(4)

    col1.metric("Total Packets", packet_count)

    col2.metric(
        "Start Time",
        datetime.datetime.fromtimestamp(start_time).strftime("%H:%M:%S")
    )

    col3.metric(
        "End Time",
        datetime.datetime.fromtimestamp(end_time).strftime("%H:%M:%S")
    )

    col4.metric("Duration (seconds)", round(duration, 2))

    # Initialize counters
    ip_count = Counter()
    protocol_count = Counter()

    # Analyze packets
    for packet in packets:

        # IP address analysis
        if packet.haslayer(scapy.IP):
            ip_src = packet[scapy.IP].src
            ip_dst = packet[scapy.IP].dst

            ip_count[ip_src] += 1
            ip_count[ip_dst] += 1

        # Protocol analysis
        if packet.haslayer(scapy.ARP):
            protocol_count["ARP"] += 1

        elif packet.haslayer(scapy.DNS):
            protocol_count["DNS"] += 1

        elif packet.haslayer(scapy.ICMP):
            protocol_count["ICMP"] += 1

        elif packet.haslayer(scapy.TCP):
            protocol_count["TCP"] += 1

        elif packet.haslayer(scapy.UDP):
            protocol_count["UDP"] += 1

        else:
            protocol_count["Other"] += 1

    # Display IP addresses
    st.subheader("IP Addresses")

    if ip_count:
        ip_df = pd.DataFrame(
            ip_count.items(),
            columns=["IP Address", "Packet Count"]
        ).sort_values(by="Packet Count", ascending=False)

        st.dataframe(ip_df, use_container_width=True)

    else:
        st.info("No IPv4 packets found.")

    # Display protocol statistics
    st.subheader("Protocol Distribution")

    if protocol_count:
        protocol_df = pd.DataFrame(
            protocol_count.items(),
            columns=["Protocol", "Packet Count"]
        ).sort_values(by="Packet Count", ascending=False)

        col1, col2 = st.columns(2)

        with col1:
            st.dataframe(protocol_df, use_container_width=True)

        with col2:
            fig = px.pie(
                protocol_df,
                names="Protocol",
                values="Packet Count",
                title="Protocol Distribution"
            )

            st.plotly_chart(fig, use_container_width=True)

else:
    st.info("Please upload a PCAP or PCAPNG file to begin analysis.")
