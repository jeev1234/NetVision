import pandas as pd
import plotly.express as px
import plotly.graph_objs as go
import os

class TrafficAnalyzer:
    def __init__(self, csv_path='data/network_traffic.csv'):
        self.csv_path = csv_path
        # Create empty DataFrame with required columns if file doesn't exist
        if not os.path.exists(csv_path) or os.path.getsize(csv_path) == 0:
            self.df = pd.DataFrame(columns=[
                'timestamp', 'source_ip', 'destination_ip', 
                'source_port', 'destination_port', 
                'protocol', 'packet_length'
            ])
        else:
            self.df = pd.read_csv(csv_path)
    
    def protocol_distribution(self):
        """Analyze protocol distribution"""
        if self.df.empty:
            # Return empty series if no data
            return pd.Series(dtype='int64')
        return self.df['protocol'].value_counts()
    
    def top_talkers(self, top_n=5):
        """Find top network talkers"""
        if self.df.empty:
            # Return empty series if no data
            return pd.Series(dtype='int64')
        source_counts = self.df['source_ip'].value_counts()
        return source_counts.head(top_n)
    
    def generate_protocol_pie_chart(self):
        """Generate interactive pie chart for protocol distribution"""
        proto_dist = self.protocol_distribution()
        if proto_dist.empty:
            # Create an empty figure with a message if no data
            fig = go.Figure()
            fig.add_annotation(
                text="No network data captured yet. Start capturing packets to see protocol distribution.",
                showarrow=False,
                font=dict(size=14)
            )
            return fig.to_html(full_html=False)
        
        fig = px.pie(
            values=proto_dist.values, 
            names=proto_dist.index, 
            title='Network Protocol Distribution'
        )
        return fig.to_html(full_html=False)