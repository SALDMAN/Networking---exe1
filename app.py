import streamlit as str
import scapy.all as scapy
import datetime
import io
from collections import Counter
import pandas 
import plotly.express as px

#It configures our page settings.
str.set_page_config(
page_title="Wireshark analyzer",
page_icon= "🖧",
layout="wide"
)

#Set title
str.title("🖧 Wireshark Analyzer")

str.write("Upload a PCAP or PCAPNG file ")

uploaded_file = str.file_uploader(
    "choose pcap or pcapng file",
    type= ["pcap", "pcapng"]
)

# Read and analyze the uploaded file
if uploaded_file is not None:
    packets = scapy.rdpcap(uploaded_file)

    # Number of packets
    packet_count = len(packets)


    # Start and end times
    start_time = float(packets[0].time)
    end_time = float(packets[-1].time)

    duration = end_time - start_time

    # Display information
    str.subheader("Capture Information")
    col1 ,col2, col3, col4 = str.columns(4)
    col1.metric( "Number of total puckets", packet_count)

    col2.metric(
        "start time:",
        datetime.datetime.fromtimestamp(start_time).strftime("%H:%M:%S")
    )
    col3.metric(
        "End time",
          datetime.datetime.fromtimestamp(end_time).strftime("%H:%M:%S")
    )

    col4.metric("Duration :", round(duration, 2))

ip_count =Counter()
protocol_count =Counter()

for packet in packets:
    if packet.haslayer(scapy.IP):

      ip_src = packet[scapy.IP].src
      ip_dst = packet[scapy.IP].dst

      ip_count[ip_src] += 1
      ip_count[ip_dst] += 1

    if packet.haslayer(scapy.ARP):
       protocol_count["DNS"] += 1       

    elif packet.haslayer(scapy.DNS):
            protocol_count["DNS"] += 1
    elif packet.haslayer(scapy.ICMP):
            protocol_count["ICMP"] += 1

    elif packet.haslayer(scapy.TCP):
            protocol_count["TCP"] += 1

    elif packet.haslayer(scapy.UDP):
            protocol_count["UDP"] += 1

str.subheader("IP Addresses : ")







