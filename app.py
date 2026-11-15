
import streamlit as str
import scapy.all as scapy
from scapy.layers.http import HTTPRequest, HTTPResponse
import datetime
from collections import Counter, defaultdict, deque
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

        # HTTP Transactions

        str.subheader("HTTP Transactions")

        pending_requests = defaultdict(deque)
        transactions = []

        def get_text(value):
            if value is None:
                return ""

            if isinstance(value, bytes):
                return value.decode("utf-8", errors="replace")

            return str(value)

        for frame_number, packet in enumerate(packets, start=1):

            if not packet.haslayer(scapy.TCP):
                continue

            if packet.haslayer(scapy.IP):
                ip_src = packet[scapy.IP].src
                ip_dst = packet[scapy.IP].dst

            elif packet.haslayer(scapy.IPv6):
                ip_src = packet[scapy.IPv6].src
                ip_dst = packet[scapy.IPv6].dst

            else:
                continue

            tcp_src = packet[scapy.TCP].sport
            tcp_dst = packet[scapy.TCP].dport

            current_flow = (
                ip_src,
                ip_dst,
                tcp_src,
                tcp_dst
            )

            # Find HTTP requests
            if packet.haslayer(HTTPRequest):

                request = packet[HTTPRequest]

                request_data = {
                    "Host": get_text(request.Host),
                    "Method": get_text(request.Method),
                    "URI": get_text(request.Path),
                    "Source IP": ip_src,
                    "Destination IP": ip_dst,
                    "Source Port": tcp_src,
                    "Destination Port": tcp_dst,
                    "Request Frame": frame_number,
                    "Request Time": float(packet.time)
                }

                pending_requests[current_flow].append(request_data)

            # Find HTTP responses
            elif packet.haslayer(HTTPResponse):

                response = packet[HTTPResponse]

                request_flow = (
                    ip_dst,
                    ip_src,
                    tcp_dst,
                    tcp_src
                )

                if pending_requests[request_flow]:

                    request_data = pending_requests[request_flow].popleft()

                    response_time = float(packet.time)

                    response_data = {
                        "Host": request_data["Host"],
                        "Method": request_data["Method"],
                        "URI": request_data["URI"],
                        "Source IP": request_data["Source IP"],
                        "Destination IP": request_data["Destination IP"],
                        "Source Port": request_data["Source Port"],
                        "Destination Port": request_data["Destination Port"],
                        "Status Code": get_text(response.Status_Code),
                        "Response Time (ms)": round(
                            (response_time - request_data["Request Time"]) * 1000, 3
                        ),
                        "Request Frame": request_data["Request Frame"],
                        "Response Frame": frame_number
                    }

                    transactions.append(response_data)

        # Display HTTP transactions
        if transactions:

            transaction_df = pd.DataFrame(transactions)

            str.dataframe(
                transaction_df,
                use_container_width=True,
                hide_index=True
            )

            # Select a transaction
            str.subheader("Transaction Details")

            transaction_options = [
                f"Transaction {i + 1} - "
                f"{transaction['Method']} "
                f"{transaction['URI']} "
                f"(Frames {transaction['Request Frame']}-"
                f"{transaction['Response Frame']})"
                for i, transaction in enumerate(transactions)
            ]

            selected_transaction = str.selectbox(
                "Choose a transaction:",
                transaction_options
            )

            selected_index = transaction_options.index(selected_transaction)

            selected_data = transactions[selected_index]

            # Display selected transaction information
            col1, col2 = str.columns(2)

            with col1:
                str.write("**Request Information**")
                str.write("Host:", selected_data["Host"])
                str.write("Method:", selected_data["Method"])
                str.write("URI:", selected_data["URI"])
                str.write("Source IP:", selected_data["Source IP"])
                str.write("Destination IP:", selected_data["Destination IP"])
                str.write("Source Port:", selected_data["Source Port"])
                str.write("Destination Port:", selected_data["Destination Port"])
                str.write("Request Frame:", selected_data["Request Frame"])

            with col2:
                str.write("**Response Information**")
                str.write("Status Code:", selected_data["Status Code"])
                str.write("Response Time (ms):", selected_data["Response Time (ms)"])
                str.write("Response Frame:", selected_data["Response Frame"])

        else:
            str.info("No complete HTTP transactions were found.")

else:
    str.info("Please upload a PCAP or PCAPNG file to begin analysis.")
