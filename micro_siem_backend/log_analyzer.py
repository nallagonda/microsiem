"""
Log Analysis and Anomaly Detection Orchestrator

This module serves as the main coordinator for log analysis in the Micro SIEM system.
It handles log file parsing, exploratory data analysis (EDA) visualization generation,
and orchestrates multiple machine learning models for anomaly detection.

Key Components:
- Log file ingestion and preprocessing
- EDA plot generation (action distribution, threat distribution, bytes scatter plots)
- Multi-model anomaly detection using Isolation Forest, Autoencoder, and VAE
- Results aggregation and JSON output for web interface consumption

The module integrates with the Flask backend to provide comprehensive log analysis
capabilities through a unified interface.
"""

import os
import re
import json
import pandas as pd
import logging
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend for server environments
import matplotlib.pyplot as plt

# Import anomaly detection modules
from isolationforest import get_anomalies_by_isolationforest
from autoencoder import get_anomalies_by_autoencoder
from vae import get_anomalies_by_vae

logger = logging.getLogger(__name__)

def generate_eda_plots(df, file_path):
    """
    Generate exploratory data analysis (EDA) plots for log visualization.

    Creates three types of plots to help analysts understand the log data:
    1. Action distribution (bar chart) - shows ALLOW/BLOCK patterns
    2. Threat distribution (pie chart) - shows threat category frequencies
    3. Bytes sent vs received (scatter plot) - shows data transfer patterns

    Args:
        df (pd.DataFrame): The log data dataframe
        file_path (str): Path to the original log file (used for naming plot files)

    Returns:
        list: List of generated plot filenames (relative names for web serving)
    """
    graphs = []

    # Plot 1: Action distribution - visualize how many requests were allowed vs blocked
    plt.figure(figsize=(8, 6))
    df['action'].value_counts().plot(kind='bar')
    plt.title('Action Distribution')
    plt.xlabel('Action')
    plt.ylabel('Count')
    plot_file = file_path.replace('.log', '_eda_action.png')
    plt.savefig(plot_file)
    plt.close()
    graphs.append('eda_action.png')

    # Plot 2: Threat distribution - show the proportion of different threat types
    plt.figure(figsize=(8, 6))
    df['threat'].value_counts().plot(kind='pie', autopct='%1.1f%%')
    plt.title('Threat Distribution')
    plot_file = file_path.replace('.log', '_eda_threat.png')
    plt.savefig(plot_file)
    plt.close()
    graphs.append('eda_threat.png')

    # Plot 3: Bytes sent vs received scatter - identify unusual data transfer patterns
    plt.figure(figsize=(8, 6))
    plt.scatter(df['bytes_sent'], df['bytes_rec'], alpha=0.5)
    plt.title('Bytes Sent vs Received')
    plt.xlabel('Bytes Sent')
    plt.ylabel('Bytes Received')
    plot_file = file_path.replace('.log', '_eda_bytes.png')
    plt.savefig(plot_file)
    plt.close()
    graphs.append('eda_bytes.png')

    return graphs

def analyze_log(file_path):
    """
    Main function to analyze log files for anomalies using multiple ML models.

    This function orchestrates the complete analysis pipeline:
    1. Load and preprocess the log file
    2. Generate EDA plots for visualization
    3. Run anomaly detection with multiple algorithms (Isolation Forest, Autoencoder, VAE)
    4. Aggregate results and save to JSON for web interface consumption

    Args:
        file_path (str): Path to the log file to analyze

    The function is designed to be robust - if one model fails, others continue running.
    Results are saved alongside the original log file with .analysis.json extension.
    """
    # Define the expected column structure for Zscaler NSS web logs
    cols = ['time_gen','time_rec','action','rule','url','cat','user','src_ip','dst_ip',
            'src_port','dst_port','proto','method','status','bytes_sent','bytes_rec',
            'ua','ref','loc','dept','reason','req_id','app','threat','country',
            'threat_cat','file_type']

    # Load the log file as a tab-separated values file without headers
    df = pd.read_csv(file_path, sep='\t', header=None, names=cols)

    # Clean data: replace NaN values with empty strings to ensure JSON serialization works
    df = df.fillna('')
    logger.info(f"Loaded dataframe with shape: {df.shape}")

    # Generate exploratory data analysis plots for the web interface
    graphs = generate_eda_plots(df, file_path)

    # Initialize dictionary to store results from different anomaly detection models
    anomalies = {}

    # Run Isolation Forest anomaly detection
    try:
        result_isolationforest = get_anomalies_by_isolationforest(df)
        # Replace any NaN values with None for JSON compatibility
        result_isolationforest = result_isolationforest.where(result_isolationforest.notna(), None)
        anomalies['isolationforest'] = result_isolationforest.to_dict('records')
        logger.info(f"IsolationForest found {len(anomalies['isolationforest'])} anomalies")
    except Exception as e:
        logger.error(f"Error in isolationforest analysis: {e}")
        anomalies['isolationforest'] = []

    # Run Autoencoder anomaly detection
    try:
        result_autoencoder = get_anomalies_by_autoencoder(df)
        result_autoencoder = result_autoencoder.where(result_autoencoder.notna(), None)
        anomalies['autoencoder'] = result_autoencoder.to_dict('records')
        logger.info(f"Autoencoder found {len(anomalies['autoencoder'])} anomalies")
    except Exception as e:
        logger.error(f"Error in autoencoder analysis: {e}")
        anomalies['autoencoder'] = []

    # Run Variational Autoencoder anomaly detection
    try:
        result_vae = get_anomalies_by_vae(df)
        result_vae = result_vae.where(result_vae.notna(), None)
        anomalies['vae'] = result_vae.to_dict('records')
        logger.info(f"VAE found {len(anomalies['vae'])} anomalies")
    except Exception as e:
        logger.error(f"Error in VAE analysis: {e}")
        anomalies['vae'] = []

    # Save the complete analysis results to a JSON file
    result_path = file_path + '.analysis.json'
    with open(result_path, 'w') as f:
        json.dump({'anomalies': anomalies, 'graphs': graphs}, f, indent=4)

    # Calculate and log total anomalies found across all models
    total_anoms = sum(len(lst) for lst in anomalies.values())
    logger.info(f"Analysis complete for {file_path}. Found {total_anoms} total anomalies.")

if __name__ == "__main__":
    # Standalone testing of the log analyzer
    # This allows running the analysis directly for testing purposes
    test_log_path = 'data/staging/test.log'
    analyze_log(test_log_path)