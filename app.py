
import streamlit as str
import scapy.all as scapy
import datetime
import io
from collections import Counter
import pandas as pd
import plotly.express as px

# It configures our page settings.
str.set_page_config(
    page_title="Wireshark analyzer",
    page_icon="🖧",
    layout="wide"
)

# Set title
str.title("🖧 Wireshark Analyzer")

str.write("Upload a PCAP or PCAPNG file")

uploaded_file = str.file_uploader(
    "choose pcap or pcapng file",
    type=["pcap", "pcapng"]
)

# Read and analyze the uploaded file
if uploaded_file is not None:
    packets = scapy.rdpcap(uploaded_file)

    if len(packets) == 0:
        str.warning("The uploaded file contains no packets.")

    else:
        # Number of packets
        packet_count = len(packets)

        # Start and end times
        start_time = float(packets[0].time)
        end_time = float(packets[-1].time)

        duration = end_time - start_time

        # Display information
        str.subheader("Capture Information")
        col1, col2, col3, col4 = str.columns(4)

        col1.metric("Number of total packets", packet_count)

        col2.metric(
            "Start time:",
            datetime.datetime.fromtimestamp(start_time).strftime("%H:%M:%S")
        )

        col3.metric(
            "End time",
            datetime.datetime.fromtimestamp(end_time).strftime("%H:%M:%S")
        )

        col4.metric("Duration:", round(duration, 2))

        # Count IP addresses and protocols
        ip_count = Counter()
        protocol_count = Counter()

        for packet in packets:

            if packet.haslayer(scapy.IP):
                ip_src = packet[scapy.IP].src
                ip_dst = packet[scapy.IP].dst

                ip_count[ip_src] += 1
                ip_count[ip_dst] += 1

            elif packet.haslayer(scapy.IPv6):
                ip_src = packet[scapy.IPv6].src
                ip_dst = packet[scapy.IPv6].dst

                ip_count[ip_src] += 1
                ip_count[ip_dst] += 1

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
        str.subheader("IP Addresses")

        ip_data = pd.DataFrame(
            ip_count.most_common(10),
            columns=["IP Address", "Number of Appearances"]
        )

        str.dataframe(ip_data, use_container_width=True)

        # Display protocols
        str.subheader("Main Protocols")

        protocol_data = pd.DataFrame(
            protocol_count.most_common(),
            columns=["Protocol", "Number of Packets"]
        )

        str.dataframe(protocol_data, use_container_width=True)




        # Traffic volume over time
        traffic_data = {}

        for packet in packets:
            second = int(float(packet.time) - start_time)
            packet_size = len(packet)

            traffic_data[second] = traffic_data.get(second, 0) + packet_size

        traffic_df = pd.DataFrame(
            list(traffic_data.items()),
            columns=["Second", "Bytes"]
        )

        str.subheader("Traffic Volume Over Time")

        fig = px.line(
            traffic_df,
            x="Second",
            y="Bytes",
            title="Network Traffic Volume per Second",
            labels={
                "Second": "Time (seconds)",
                "Bytes": "Traffic Volume (bytes)"
            }
        )

        str.plotly_chart(fig, use_container_width=True)