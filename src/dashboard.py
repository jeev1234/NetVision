import dash
from dash import dcc, html
from dash.dependencies import Input, Output
import plotly.express as px
import plotly.graph_objs as go
import pandas as pd
import threading
import time
import socket
import os
import sys

# Add the parent directory to the path to import our modules
current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
sys.path.insert(0, parent_dir)
sys.path.insert(0, current_dir)

from src.network_scanner import NetworkScanner
from src.traffic_analyzer import TrafficAnalyzer
from src.performance_monitor import PerformanceMonitor
from src.network_metrics_manager import NetworkMetricsManager
from src.config import (
    NETWORK_RANGE,
    DASHBOARD_UPDATE_INTERVAL,
    DEFAULT_MONITORING_TARGETS,
    DASHBOARD_HOST,
    DASHBOARD_PORT,
    DATA_DIR,
    TRAFFIC_CSV
)

# Global metrics manager
metrics_manager = None

# Initialize Dash app with assets folder at parent directory
app = dash.Dash(__name__, 
                title="NetVision Dashboard",
                assets_folder=os.path.join(parent_dir, 'assets'),
                suppress_callback_exceptions=True)

# App layout
app.layout = html.Div([
    html.H1("NetVision Network Monitor Dashboard"),
    html.H3(f"Monitoring Network: {NETWORK_RANGE}", style={"textAlign": "center", "color": "#2980b9"}),
    
    # Device Overview Section
    html.Div([
        html.H2("Network Devices"),
        dcc.Tabs([
            dcc.Tab(label="Active Devices", children=[
                html.Div(id="device-count", className="metric-header"),
                html.Div(id="devices-loading", className="loading-container", children=[
                    html.Div(className="loading-spinner"),
                    html.Div("Scanning network for devices...", className="loading-text")
                ]),
                html.Div(id="device-table")
            ]),
            dcc.Tab(label="Top Talkers", children=[
                html.H3("Top Network Talkers"),
                html.Div(id="talkers-loading", className="loading-container", children=[
                    html.Div(className="loading-spinner"),
                    html.Div("Analyzing network traffic data...", className="loading-text")
                ]),
                html.Div(id="top-talkers-table"),
                dcc.Graph(id="top-talkers-graph")
            ])
        ])
    ], className="dashboard-section"),
    
    # Network Traffic Section
    html.Div([
        html.H2("Network Traffic"),
        dcc.Tabs([
            dcc.Tab(label="Real-time Bandwidth", children=[
                html.Div(id="bandwidth-loading", className="loading-container", children=[
                    html.Div(className="loading-spinner"),
                    html.Div("Collecting bandwidth data...", className="loading-text")
                ]),
                dcc.Graph(id="bandwidth-graph")
            ]),
            dcc.Tab(label="Protocol Distribution", children=[
                html.Div(id="protocols-loading", className="loading-container", children=[
                    html.Div(className="loading-spinner"),
                    html.Div("Analyzing protocol distribution...", className="loading-text")
                ]),
                dcc.Graph(id="protocol-distribution")
            ]),
            dcc.Tab(label="Recent Connections", children=[
                html.Div(id="connections-loading", className="loading-container", children=[
                    html.Div(className="loading-spinner"),
                    html.Div("Tracking network connections...", className="loading-text")
                ]),
                html.Div(id="connection-stats"),
                html.Div(id="recent-connections-table")
            ])
        ])
    ], className="dashboard-section"),
    
    # Performance Metrics Section
    html.Div([
        html.H2("Performance Metrics"),
        dcc.Dropdown(
            id="performance-target",
            options=[],
            placeholder="Select a target to view metrics"
        ),
        dcc.Tabs([
            dcc.Tab(label="Latency", children=[
                html.Div(id="latency-loading", className="loading-container", children=[
                    html.Div(className="loading-spinner"),
                    html.Div("Measuring network latency...", className="loading-text")
                ]),
                html.Div(id="latency-container"),
                dcc.Graph(id="latency-graph")
            ]),
            dcc.Tab(label="Packet Loss", children=[
                html.Div(id="packet-loss-container"),
                dcc.Graph(id="packet-loss-graph")
            ]),
            dcc.Tab(label="Network Jitter", children=[
                html.Div(id="jitter-container"),
                dcc.Graph(id="jitter-graph")
            ]),
            dcc.Tab(label="DNS Resolution", children=[
                html.Div(id="dns-container"),
                dcc.Graph(id="dns-resolution-graph")
            ]),
            dcc.Tab(label="Connection Time", children=[
                html.Div(id="connection-time-container"),
                dcc.Graph(id="connection-time-graph")
            ])
        ])
    ], className="dashboard-section"),
    
    # Status indicator
    html.Div(id="status-indicator", className="status-indicator", children=[
        html.Span("NetVision Status: "),
        html.Span("Initializing...", id="status-text", style={"color": "#f39c12"})
    ]),
    
    # Interval components for updating data
    dcc.Interval(
        id="interval-component",
        interval=DASHBOARD_UPDATE_INTERVAL,  # Update interval from config
        n_intervals=0
    ),
    
    dcc.Interval(
        id="slow-interval-component",
        interval=30000,  # Update every 30 seconds
        n_intervals=0
    ),
    
    dcc.Interval(
        id="status-interval",
        interval=5000,  # Update every 5 seconds
        n_intervals=0
    )
], className="main-container")

# Callback for active devices section
@app.callback(
    [Output("device-count", "children"),
     Output("device-table", "children"),
     Output("performance-target", "options"),
     Output("devices-loading", "style")],
    [Input("slow-interval-component", "n_intervals")]
)
def update_device_info(n):
    if not metrics_manager:
        return "No data available", html.Div(), [], {"display": "flex"}  # Keep loading visible
    
    # Get device metrics
    devices = metrics_manager.get_metrics("devices")
    
    # Create device table
    if devices:
        device_count = f"Total active devices: {len(devices)}"
        
        # Create table data
        rows = []
        for ip, data in devices.items():
            rows.append(html.Tr([
                html.Td(ip),
                html.Td(data.get('mac', 'Unknown')),
                html.Td(f"{data.get('bandwidth_usage', {}).get('total_sent_bytes', 0) / 1024:.2f} KB"),
                html.Td(f"{data.get('bandwidth_usage', {}).get('total_received_bytes', 0) / 1024:.2f} KB"),
                html.Td(f"{data.get('protocol_distribution', {}).get('TCP', 0):.1f}%")
            ]))
        
        device_table = html.Table(
            [html.Thead(html.Tr([
                html.Th("IP Address"), html.Th("MAC Address"),
                html.Th("Data Sent"), html.Th("Data Received"), html.Th("TCP %")
            ]))] + 
            [html.Tbody(rows)]
        )
        
        # Hide loading spinner when data is available
        loading_style = {"display": "none"}
    else:
        device_count = "No active devices detected"
        device_table = html.Div("No device data available")
        # Keep loading spinner visible if no devices yet
        loading_style = {"display": "flex"}
    
    # Get performance targets for dropdown
    perf_targets = []
    if metrics_manager.performance_monitor:
        for target in metrics_manager.performance_monitor.common_destinations:
            perf_targets.append({"label": target, "value": target})
    
    return device_count, device_table, perf_targets, loading_style

# Status indicator update
@app.callback(
    [Output("status-text", "children"),
     Output("status-text", "style")],
    [Input("status-interval", "n_intervals")]
)
def update_status(n):
    if not metrics_manager:
        return "Initializing...", {"color": "#f39c12"}
    
    # Check component status
    scanner_active = metrics_manager.network_scanner is not None
    analyzer_active = metrics_manager.traffic_analyzer is not None
    monitor_active = metrics_manager.performance_monitor is not None
    
    if all([scanner_active, analyzer_active, monitor_active]):
        return "Running", {"color": "#2ecc71"}  # Green
    elif any([scanner_active, analyzer_active, monitor_active]):
        return "Partially Running", {"color": "#f39c12"}  # Orange
    else:
        return "Stopped", {"color": "#e74c3c"}  # Red

# Callback for top talkers section
@app.callback(
    [Output("top-talkers-table", "children"),
     Output("top-talkers-graph", "figure"),
     Output("talkers-loading", "style")],
    [Input("slow-interval-component", "n_intervals")]
)
def update_top_talkers(n):
    if not metrics_manager or not hasattr(metrics_manager.traffic_analyzer, 'get_top_talkers'):
        empty_fig = go.Figure()
        empty_fig.add_annotation(text="No top talkers data available", 
                              xref="paper", yref="paper",
                              x=0.5, y=0.5, showarrow=False)
        return html.Div("No top talkers data available"), empty_fig, {"display": "flex"}  # Keep loading visible
    
    try:
        # Get top talkers
        top_talkers = metrics_manager.traffic_analyzer.get_top_talkers(limit=10)
        
        if not top_talkers:
            empty_fig = go.Figure()
            empty_fig.add_annotation(text="No top talkers data available", 
                                  xref="paper", yref="paper",
                                  x=0.5, y=0.5, showarrow=False)
            return html.Div("No top talkers data available"), empty_fig, {"display": "flex"}  # Keep loading visible
        
        # Create table data
        rows = []
        ips = []
        bytes_values = []
        
        for talker in top_talkers:
            ip = talker['ip']
            total_bytes = talker['total_bytes']
            total_mb = total_bytes / (1024 * 1024)
            
            ips.append(ip)
            bytes_values.append(total_mb)
            
            rows.append(html.Tr([
                html.Td(ip),
                html.Td(f"{total_mb:.2f} MB")
            ]))
        
        # Create table
        table = html.Table(
            [html.Thead(html.Tr([
                html.Th("IP Address"), html.Th("Total Data")
            ]))] + 
            [html.Tbody(rows)]
        )
        
        # Create graph
        fig = go.Figure(data=[
            go.Bar(name='Total Traffic', x=ips, y=bytes_values)
        ])
        
        fig.update_layout(
            title="Top Network Talkers by Traffic Volume",
            xaxis_title="IP Address",
            yaxis_title="Data Transferred (MB)"
        )
        
        # Hide loading spinner when data is available
        loading_style = {"display": "none"}
        
        return table, fig, loading_style
    
    except Exception as e:
        print(f"Error updating top talkers: {e}")
        empty_fig = go.Figure()
        empty_fig.add_annotation(text="Error retrieving top talkers data", 
                              xref="paper", yref="paper",
                              x=0.5, y=0.5, showarrow=False)
        return html.Div(f"Error: {str(e)}"), empty_fig, {"display": "flex"}  # Keep loading visible

# Callback for recent connections section
@app.callback(
    [Output("connection-stats", "children"),
     Output("recent-connections-table", "children"),
     Output("connections-loading", "style")],
    [Input("slow-interval-component", "n_intervals")]
)
def update_connection_stats(n):
    if not metrics_manager:
        return html.Div("No connection data available"), html.Div("No connection data available"), {"display": "flex"}
    
    try:
        # Get recent connections
        recent_connections = metrics_manager.get_metrics("recent_connections")
        
        if not recent_connections:
            return html.Div("No recent connections detected"), html.Div("No connection data available"), {"display": "flex"}
        
        # Calculate connection statistics
        total_connections = len(recent_connections)
        avg_duration = sum(conn.get('duration', 0) for conn in recent_connections) / total_connections if total_connections > 0 else 0
        
        # Count protocols
        protocols = {}
        for conn in recent_connections:
            proto = conn.get('protocol', 'Unknown')
            protocols[proto] = protocols.get(proto, 0) + 1
        
        # Count destinations
        destinations = {}
        for conn in recent_connections:
            dst = conn.get('dst_ip', 'Unknown')
            destinations[dst] = destinations.get(dst, 0) + 1
        
        # Create stats summary
        stats_summary = html.Div([
            html.H4("Connection Statistics"),
            html.P(f"Total Connections: {total_connections}"),
            html.P(f"Average Duration: {avg_duration:.2f} seconds"),
            html.P(f"Protocol Distribution: {', '.join([f'{k}: {v}' for k, v in protocols.items()])}"),
            html.P(f"Top Destinations: {', '.join([f'{k}: {v}' for k, v in sorted(destinations.items(), key=lambda x: x[1], reverse=True)[:5]])}")
        ])
        
        # Create connections table
        rows = []
        for conn in recent_connections[:20]:  # Show top 20 recent connections
            rows.append(html.Tr([
                html.Td(conn.get('src_ip', 'Unknown')),
                html.Td(conn.get('dst_ip', 'Unknown')),
                html.Td(f"{conn.get('src_port', 'N/A')} → {conn.get('dst_port', 'N/A')}"),
                html.Td(conn.get('protocol', 'Unknown')),
                html.Td(conn.get('app_protocol', 'Unknown')),
                html.Td(f"{conn.get('duration', 0):.2f} sec"),
                html.Td(f"{(conn.get('bytes_sent', 0) + conn.get('bytes_received', 0)) / 1024:.2f} KB")
            ]))
        
        connections_table = html.Div([
            html.H4("Recent Connections"),
            html.Table(
                [html.Thead(html.Tr([
                    html.Th("Source IP"), html.Th("Destination IP"), 
                    html.Th("Ports"), html.Th("Protocol"),
                    html.Th("App Protocol"), html.Th("Duration"),
                    html.Th("Data Transferred")
                ]))] + 
                [html.Tbody(rows)]
            )
        ])
        
        # Hide loading spinner when data is available
        loading_style = {"display": "none"}
        
        return stats_summary, connections_table, loading_style
        
    except Exception as e:
        print(f"Error updating connection stats: {e}")
        return html.Div(f"Error: {str(e)}"), html.Div("No connection data available"), {"display": "flex"}

@app.callback(
    [Output("bandwidth-graph", "figure"),
     Output("bandwidth-loading", "style")],
    [Input("interval-component", "n_intervals")]
)
def update_bandwidth_graph(n):
    if not metrics_manager:
        empty_fig = go.Figure()
        empty_fig.add_annotation(text="No bandwidth data available", 
                          xref="paper", yref="paper",
                          x=0.5, y=0.5, showarrow=False)
        return empty_fig, {"display": "flex"}  # Keep loading visible
    
    bandwidth = metrics_manager.get_metrics("bandwidth")
    
    if not bandwidth:
        # Return empty figure with message
        empty_fig = go.Figure()
        empty_fig.add_annotation(text="No bandwidth data available", 
                          xref="paper", yref="paper",
                          x=0.5, y=0.5, showarrow=False)
        return empty_fig, {"display": "flex"}  # Keep loading visible
    
    # Convert to DataFrame for plotting
    upload_data = []
    download_data = []
    ips = []
    
    for ip, data in bandwidth.items():
        ips.append(ip)
        upload_data.append(data.get('upload', 0))
        download_data.append(data.get('download', 0))
    
    fig = go.Figure(data=[
        go.Bar(name='Upload (KB/s)', x=ips, y=upload_data),
        go.Bar(name='Download (KB/s)', x=ips, y=download_data)
    ])
    
    fig.update_layout(
        title="Real-time Bandwidth Usage",
        xaxis_title="IP Address",
        yaxis_title="Bandwidth (KB/s)",
        barmode='group'
    )
    
    # Hide loading spinner when data is available
    loading_style = {"display": "none"}
    
    return fig, loading_style

@app.callback(
    [Output("protocol-distribution", "figure"),
     Output("protocols-loading", "style")],
    [Input("slow-interval-component", "n_intervals")]
)
def update_protocol_distribution(n):
    if not metrics_manager:
        empty_fig = go.Figure()
        empty_fig.add_annotation(text="No protocol data available", 
                          xref="paper", yref="paper",
                          x=0.5, y=0.5, showarrow=False)
        return empty_fig, {"display": "flex"}  # Keep loading visible
    
    protocol_dist = metrics_manager.get_metrics("protocol_distribution")
    
    if not protocol_dist:
        # Return empty figure with message
        empty_fig = go.Figure()
        empty_fig.add_annotation(text="No protocol data available", 
                          xref="paper", yref="paper",
                          x=0.5, y=0.5, showarrow=False)
        return empty_fig, {"display": "flex"}  # Keep loading visible
    
    # Create two pie charts - transport and application protocols
    transport_protocols = protocol_dist.get('transport_protocols', {})
    app_protocols = protocol_dist.get('application_protocols', {})
    
    if transport_protocols and app_protocols:
        fig = go.Figure()
        
        # Transport protocols pie
        fig.add_trace(go.Pie(
            labels=list(transport_protocols.keys()),
            values=list(transport_protocols.values()),
            name="Transport Protocols",
            domain=dict(x=[0, 0.45])
        ))
        
        # App protocols pie (top 5)
        top_app_protocols = dict(list(app_protocols.items())[:5])
        fig.add_trace(go.Pie(
            labels=list(top_app_protocols.keys()),
            values=list(top_app_protocols.values()),
            name="Application Protocols",
            domain=dict(x=[0.55, 1])
        ))
        
        fig.update_layout(
            title="Protocol Distribution",
            annotations=[
                dict(text="Transport", x=0.22, y=0.5, font_size=15, showarrow=False),
                dict(text="Application", x=0.78, y=0.5, font_size=15, showarrow=False)
            ]
        )
    else:
        # Return empty figure with message
        fig = go.Figure()
        fig.add_annotation(text="No protocol data available", 
                          xref="paper", yref="paper",
                          x=0.5, y=0.5, showarrow=False)
    
    # Hide loading spinner when data is available
    loading_style = {"display": "none"}
    
    return fig, loading_style

# Callback for all performance metrics
@app.callback(
    [Output("latency-container", "children"),
     Output("latency-graph", "figure"),
     Output("packet-loss-container", "children"),
     Output("packet-loss-graph", "figure"),
     Output("jitter-container", "children"),
     Output("jitter-graph", "figure"),
     Output("dns-container", "children"),
     Output("dns-resolution-graph", "figure"),
     Output("connection-time-container", "children"),
     Output("connection-time-graph", "figure"),
     Output("latency-loading", "style")],
    [Input("performance-target", "value"),
     Input("interval-component", "n_intervals")]
)
def update_performance_metrics(target, n):
    if not metrics_manager or not target:
        empty_fig = go.Figure()
        empty_fig.add_annotation(text="No data available", 
                                xref="paper", yref="paper",
                                x=0.5, y=0.5, showarrow=False)
        
        no_data = "No data available"
        return no_data, empty_fig, no_data, empty_fig, no_data, empty_fig, no_data, empty_fig, no_data, empty_fig, {"display": "flex"}
    
    # Get performance metrics for the selected target
    perf = metrics_manager.performance_monitor.get_comprehensive_metrics(target)
    
    # Results variables
    latency_html = html.Div("No latency data available")
    latency_fig = go.Figure()
    packet_loss_html = html.Div("No packet loss data available")
    packet_loss_fig = go.Figure()
    jitter_html = html.Div("No jitter data available")
    jitter_fig = go.Figure()
    dns_html = html.Div("No DNS resolution data available")
    dns_fig = go.Figure()
    conn_time_html = html.Div("No connection time data available")
    conn_time_fig = go.Figure()
    
    # Latency metrics
    if target in perf and 'latency' in perf[target] and perf[target]['latency']:
        lat_data = perf[target]['latency']
        
        latency_html = html.Div([
            html.P(f"Current: {lat_data.get('current', 0):.2f} ms"),
            html.P(f"Min: {lat_data.get('min', 0):.2f} ms"),
            html.P(f"Max: {lat_data.get('max', 0):.2f} ms"),
            html.P(f"Avg: {lat_data.get('avg', 0):.2f} ms"),
            html.P(f"Median: {lat_data.get('median', 0):.2f} ms")
        ])
        
        # Create latency history graph
        history = lat_data.get('history', [])
        if history:
            times = [entry['timestamp'] for entry in history]
            values = [entry['value'] for entry in history]
            
            latency_fig = px.line(
                x=times, y=values,
                labels={"x": "Time", "y": "Latency (ms)"},
                title=f"Latency History for {target}"
            )
        else:
            latency_fig.add_annotation(text="No historical latency data", 
                                      xref="paper", yref="paper",
                                      x=0.5, y=0.5, showarrow=False)
    
    # Packet loss metrics
    if target in perf and 'packet_loss' in perf[target] and perf[target]['packet_loss']:
        loss_data = perf[target]['packet_loss']
        
        packet_loss_html = html.Div([
            html.P(f"Current: {loss_data.get('current', 0):.2f}%"),
            html.P(f"Min: {loss_data.get('min', 0):.2f}%"),
            html.P(f"Max: {loss_data.get('max', 0):.2f}%"),
            html.P(f"Avg: {loss_data.get('avg', 0):.2f}%")
        ])
        
        # Create packet loss history graph
        history = loss_data.get('history', [])
        if history:
            times = [entry['timestamp'] for entry in history]
            values = [entry['value'] for entry in history]
            
            packet_loss_fig = px.line(
                x=times, y=values,
                labels={"x": "Time", "y": "Packet Loss (%)"},
                title=f"Packet Loss History for {target}"
            )
        else:
            packet_loss_fig.add_annotation(text="No historical packet loss data", 
                                         xref="paper", yref="paper",
                                         x=0.5, y=0.5, showarrow=False)
    
    # Jitter metrics
    if target in perf and 'jitter' in perf[target] and perf[target]['jitter']:
        jitter_data = perf[target]['jitter']
        
        jitter_html = html.Div([
            html.P(f"Current: {jitter_data.get('current', 0):.2f} ms"),
            html.P(f"Min: {jitter_data.get('min', 0):.2f} ms"),
            html.P(f"Max: {jitter_data.get('max', 0):.2f} ms"),
            html.P(f"Avg: {jitter_data.get('avg', 0):.2f} ms")
        ])
        
        # Create jitter history graph
        history = jitter_data.get('history', [])
        if history:
            times = [entry['timestamp'] for entry in history]
            values = [entry['value'] for entry in history]
            
            jitter_fig = px.line(
                x=times, y=values,
                labels={"x": "Time", "y": "Jitter (ms)"},
                title=f"Network Jitter for {target}"
            )
        else:
            jitter_fig.add_annotation(text="No historical jitter data", 
                                    xref="paper", yref="paper",
                                    x=0.5, y=0.5, showarrow=False)
    
    # DNS resolution metrics
    if target in perf and 'dns_resolution' in perf[target] and perf[target]['dns_resolution']:
        dns_data = perf[target]['dns_resolution']
        
        dns_html = html.Div([
            html.P(f"Current: {dns_data.get('current', 0):.2f} ms"),
            html.P(f"Min: {dns_data.get('min', 0):.2f} ms"),
            html.P(f"Max: {dns_data.get('max', 0):.2f} ms"),
            html.P(f"Avg: {dns_data.get('avg', 0):.2f} ms"),
            html.P(f"Median: {dns_data.get('median', 0):.2f} ms")
        ])
        
        # Create DNS resolution history graph
        history = dns_data.get('history', [])
        if history:
            times = [entry['timestamp'] for entry in history]
            values = [entry['value'] for entry in history]
            
            dns_fig = px.line(
                x=times, y=values,
                labels={"x": "Time", "y": "Resolution Time (ms)"},
                title=f"DNS Resolution Time for {target}"
            )
        else:
            dns_fig.add_annotation(text="No historical DNS resolution data", 
                                 xref="paper", yref="paper",
                                 x=0.5, y=0.5, showarrow=False)
    
    # Connection time metrics
    if target in perf and 'connection_time' in perf[target] and perf[target]['connection_time']:
        conn_time_data = perf[target]['connection_time']
        
        conn_time_html = html.Div([
            html.P(f"Current: {conn_time_data.get('current', 0):.2f} ms"),
            html.P(f"Min: {conn_time_data.get('min', 0):.2f} ms"),
            html.P(f"Max: {conn_time_data.get('max', 0):.2f} ms"),
            html.P(f"Avg: {conn_time_data.get('avg', 0):.2f} ms"),
            html.P(f"Retry Attempts: {conn_time_data.get('retry_attempts', 0)}")
        ])
        
        # Create connection time history graph
        history = conn_time_data.get('history', [])
        if history:
            times = [entry['timestamp'] for entry in history]
            values = [entry['value'] for entry in history]
            
            conn_time_fig = px.line(
                x=times, y=values,
                labels={"x": "Time", "y": "Connection Time (ms)"},
                title=f"TCP Connection Establishment Time for {target}"
            )
        else:
            conn_time_fig.add_annotation(text="No historical connection time data", 
                                       xref="paper", yref="paper",
                                       x=0.5, y=0.5, showarrow=False)
    
    # Hide loading spinner when data is available
    loading_style = {"display": "none"}
    
    return (latency_html, latency_fig, 
            packet_loss_html, packet_loss_fig,
            jitter_html, jitter_fig,
            dns_html, dns_fig,
            conn_time_html, conn_time_fig,
            loading_style)

def initialize_metrics_manager():
    global metrics_manager
    
    # Ensure data directory exists
    data_dir = os.path.join(parent_dir, DATA_DIR)
    if not os.path.exists(data_dir):
        os.makedirs(data_dir)
    csv_path = os.path.join(data_dir, TRAFFIC_CSV)
    
    # Initialize components
    print(f"Initializing NetVision components for network: {NETWORK_RANGE}...")
    scanner = NetworkScanner(network=NETWORK_RANGE)
    analyzer = TrafficAnalyzer(network_scanner=scanner, csv_path=csv_path)
    monitor = PerformanceMonitor()
    
    # Create metrics manager
    metrics_manager = NetworkMetricsManager(
        network_scanner=scanner,
        traffic_analyzer=analyzer,
        performance_monitor=monitor
    )
    
    # Start monitoring
    print("Starting network monitoring...")
    metrics_manager.start()
    
    # Add default monitoring targets
    for target in DEFAULT_MONITORING_TARGETS:
        metrics_manager.add_performance_target(target)
    
    print("NetVision monitoring started successfully!")

if __name__ == "__main__":
    print("Initializing NetVision Dashboard...")
    
    # Create assets directory if it doesn't exist
    assets_dir = os.path.join(parent_dir, 'assets')
    if not os.path.exists(assets_dir):
        os.makedirs(assets_dir)
    
    # Start metrics manager in a separate thread
    threading.Thread(target=initialize_metrics_manager, daemon=True).start()
    
    # Wait for initialization
    time.sleep(3)  # Increased wait time for better initialization
    
    # Start the Dash server
    print(f"Starting dashboard server on http://{DASHBOARD_HOST}:{DASHBOARD_PORT}/")
    app.run_server(debug=False, use_reloader=False, host=DASHBOARD_HOST, port=DASHBOARD_PORT)