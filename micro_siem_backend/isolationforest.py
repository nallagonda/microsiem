"""
Isolation Forest-based Anomaly Detection Module

This module implements anomaly detection using the Isolation Forest algorithm.
Isolation Forest is an unsupervised machine learning algorithm that isolates anomalies
by randomly partitioning data points. Anomalies are easier to isolate and thus have
shorter path lengths in the forest.

The algorithm is efficient for high-dimensional data and doesn't require distance or density
calculations. It works by building multiple isolation trees and scoring anomalies based
on how easily they can be isolated.
"""

from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import numpy as np
import logging

logger = logging.getLogger(__name__)

def get_anomalies_by_isolationforest(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect anomalies in log data using Isolation Forest.

    This function extracts numeric features from log entries, normalizes them,
    and applies Isolation Forest to identify anomalous patterns.

    Args:
        df (pd.DataFrame): Input dataframe containing Zscaler NSS web log entries

    Returns:
        pd.DataFrame: Top 10 anomalous log entries with their anomaly scores and metadata

    The algorithm:
    1. Extracts relevant numeric features from logs
    2. Normalizes features for consistent scaling
    3. Trains Isolation Forest on the data
    4. Scores each point (negative scores = more anomalous)
    5. Returns top anomalies based on score ranking
    """
    # Define the expected column structure for Zscaler NSS web logs
    cols=['time_gen', 'time_rec', 'action', 'rule', 'url', 
                        'cat', 'user', 'src_ip', 'dst_ip', 'src_port', 
                        'dst_port', 'proto', 'method', 'status', 
                        'bytes_sent', 'bytes_rec', 'ua', 'ref', 
                        'loc', 'dept', 'reason', 'req_id', 'app', 
                        'threat', 'country', 'threat_cat', 'file_type']
    # Extract and create numeric features suitable for anomaly detection
    # These features capture quantitative aspects of network traffic that might indicate anomalies
    features = df[['bytes_sent', 'bytes_rec', 'src_port']].copy()
    features['status_code'] = pd.to_numeric(df['status'])                    # Convert HTTP status codes to numeric
    features['is_block'] = (df['action'] == 'BLOCK').astype(int)            # Binary flag for blocked requests
    features['threat_score'] = df['threat'].map({                           # Map threat categories to severity scores
        'Malware':3, 'Phishing':2, 'Command-Control':3, 'NONE':0
    }).fillna(0)  # Fill missing threats with 0 (no threat)

    # Normalize features to prevent scale differences from affecting the algorithm
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features.fillna(0))  # Fill any remaining NaN values

    # Train the Isolation Forest model
    # contamination=0.1 means we expect about 10% of data to be anomalies
    # No labels needed - this is unsupervised learning
    model = IsolationForest(contamination=0.1, random_state=42)
    anomalies = model.fit_predict(X_scaled)  # Returns -1 for anomalies, 1 for normal points

    # Calculate anomaly scores for ranking all data points
    # decision_function returns negative scores; we negate them so higher values = more anomalous
    df['anomaly_score'] = -model.decision_function(X_scaled)

    # Extract the top 10 most anomalous entries based on anomaly score
    top = df.sort_values('anomaly_score', ascending=False).head(10)
    result_df = top[['user', 'url', 'threat', 'bytes_rec', 'anomaly_score', 'src_ip', 'dst_ip', 'action']].copy()
    result_df['line'] = top.index + 1  # Add 1-based line number for log reference
    logger.info(f"IsolationForest processed {len(df)} records, found {len(result_df)} anomalies")
    logger.debug(f"Anomalies: {result_df.to_dict('records')}")
    return result_df

if __name__ == "__main__":
    # Example usage for testing the Isolation Forest anomaly detection
    # Load a sample log file and run anomaly detection
    cols=['time_gen', 'time_rec', 'action', 'rule', 'url',
                         'cat', 'user', 'src_ip', 'dst_ip', 'src_port',
                         'dst_port', 'proto', 'method', 'status',
                         'bytes_sent', 'bytes_rec', 'ua', 'ref',
                         'loc', 'dept', 'reason', 'req_id', 'app',
                         'threat', 'country', 'threat_cat', 'file_type']
    df = pd.read_csv("/Users/nallagonda/Kiran/tenex_project/micro_siem_backend/data/staging/admin_zscaler_nss_web_poc_1768194856996.log",
                     sep='\t', header=None, names=cols)
    result = get_anomalies_by_isolationforest(df)
    print("Isolation Forest anomaly detection results:")
    print(result)
