import os
import re
import json
import pandas as pd
import logging
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
from isolationforest import get_anomalies_by_isolationforest
from autoencoder import get_anomalies_by_autoencoder
from vae import get_anomalies_by_vae

logger = logging.getLogger(__name__)

def generate_eda_plots(df, file_path):
    """Generate EDA plots and return list of graph filenames."""
    graphs = []
    # Plot 1: Action distribution
    plt.figure(figsize=(8, 6))
    df['action'].value_counts().plot(kind='bar')
    plt.title('Action Distribution')
    plt.xlabel('Action')
    plt.ylabel('Count')
    plot_file = file_path.replace('.log', '_eda_action.png')
    plt.savefig(plot_file)
    plt.close()
    graphs.append('eda_action.png')

    # Plot 2: Threat distribution
    plt.figure(figsize=(8, 6))
    df['threat'].value_counts().plot(kind='pie', autopct='%1.1f%%')
    plt.title('Threat Distribution')
    plot_file = file_path.replace('.log', '_eda_threat.png')
    plt.savefig(plot_file)
    plt.close()
    graphs.append('eda_threat.png')

    # Plot 3: Bytes sent vs received scatter
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
    Analyzes the log file for anomalies.
    """
    cols = ['time_gen','time_rec','action','rule','url','cat','user','src_ip','dst_ip',
            'src_port','dst_port','proto','method','status','bytes_sent','bytes_rec',
            'ua','ref','loc','dept','reason','req_id','app','threat','country',
            'threat_cat','file_type']
    df = pd.read_csv(file_path, sep='\t', header=None, names=cols)
    df = df.fillna('')  # Replace NaN with empty string for JSON serialization
    logger.info(f"Loaded df with shape: {df.shape}")
    graphs = generate_eda_plots(df, file_path)
    anomalies = {}
    try:
        result_isolationforest = get_anomalies_by_isolationforest(df)
        result_isolationforest = result_isolationforest.where(result_isolationforest.notna(), None)
        anomalies['isolationforest'] = result_isolationforest.to_dict('records')
        logger.info(f"IsolationForest found {len(anomalies['isolationforest'])} anomalies")
    except Exception as e:
        logger.error(f"Error in isolationforest: {e}")
        anomalies['isolationforest'] = []

    try:
        result_autoencoder = get_anomalies_by_autoencoder(df)
        result_autoencoder = result_autoencoder.where(result_autoencoder.notna(), None)
        anomalies['autoencoder'] = result_autoencoder.to_dict('records')
        logger.info(f"Autoencoder found {len(anomalies['autoencoder'])} anomalies")
    except Exception as e:
        logger.error(f"Error in autoencoder: {e}")
        anomalies['autoencoder'] = []

    try:
        result_vae = get_anomalies_by_vae(df)
        result_vae = result_vae.where(result_vae.notna(), None)
        anomalies['vae'] = result_vae.to_dict('records')
        logger.info(f"VAE found {len(anomalies['vae'])} anomalies")
    except Exception as e:
        logger.error(f"Error in vae: {e}")
        anomalies['vae'] = []

    # Save results to a JSON file
    result_path = file_path + '.analysis.json'
    with open(result_path, 'w') as f:
        json.dump({'anomalies': anomalies, 'graphs': graphs}, f, indent=4)

    total_anoms = sum(len(lst) for lst in anomalies.values())
    logger.info(f"Analysis complete for {file_path}. Found {total_anoms} total anomalies.")

if __name__ == "__main__":
    # For testing
    analyze_log('data/staging/test.log')