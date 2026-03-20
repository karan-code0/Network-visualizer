from scapy.all import sniff, IP, conf, TCP, UDP, ICMP
import plotly.graph_objs as go
from dash import Dash, dcc, html, Input, Output
import threading
import time
import requests
from collections import Counter, deque

incoming_ips = Counter()
outgoing_ips = Counter()
packet_timeline = deque(maxlen=100)
geolocation_cache = {}
protocol_counts = Counter()

def geolocate_ip(ip):
    if ip in geolocation_cache:
        return geolocation_cache[ip]
    try:
        res = requests.get(f"http://ip-api.com/json/{ip}", timeout=3).json()
        data = {
            "lat": res.get("lat"),
            "lon": res.get("lon"),
            "country": res.get("country", "Unknown")
        }
        geolocation_cache[ip] = data
        return data
    except:
        return {"lat": None, "lon": None, "country": "Unknown"}

def process_packet(packet):
    if packet.haslayer(IP):
        src = packet[IP].src
        dst = packet[IP].dst
        packet_timeline.append(time.time())

        if packet.haslayer(TCP):
            protocol_counts['TCP'] += 1
        elif packet.haslayer(UDP):
            protocol_counts['UDP'] += 1
        elif packet.haslayer(ICMP):
            protocol_counts['ICMP'] += 1
        else:
            protocol_counts['Other'] += 1

        if src.startswith("192.168.") or src.startswith("10."):
            outgoing_ips[dst] += 1
        else:
            incoming_ips[src] += 1

def packet_sniffer():
    conf.sniff_promisc = True
    sniff(prn=process_packet, store=False)

app = Dash(__name__)
app.layout = html.Div([
    html.H1("Network Traffic Analyzer"),
    dcc.Interval(id="interval", interval=2000),

    dcc.Graph(id="traffic-bar"),
    dcc.Graph(id="traffic-line"),
    dcc.Graph(id="protocol-pie")
])

@app.callback(
    [Output("traffic-bar", "figure"),
     Output("traffic-line", "figure"),
     Output("protocol-pie", "figure")],
    Input("interval", "n_intervals")
)
def update(n):
    bar = go.Figure()
    bar.add_bar(x=list(incoming_ips.keys()), y=list(incoming_ips.values()), name="Incoming")
    bar.add_bar(x=list(outgoing_ips.keys()), y=list(outgoing_ips.values()), name="Outgoing")

    line = go.Figure()
    line.add_scatter(x=list(packet_timeline), y=list(range(len(packet_timeline))))

    pie = go.Figure(go.Pie(
        labels=list(protocol_counts.keys()),
        values=list(protocol_counts.values())
    ))

    return bar, line, pie

if __name__ == "__main__":
    threading.Thread(target=packet_sniffer, daemon=True).start()
    app.run(debug=True)
