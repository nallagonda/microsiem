"""
Autoencoder-based Anomaly Detection Module

This module implements anomaly detection in log data using an Autoencoder neural network.
Autoencoders learn to compress and reconstruct input data. Anomalies are detected by
measuring reconstruction errors - high error indicates potential anomalies.

The model uses a simple feedforward architecture with encoder and decoder layers.
Features are extracted from log entries and normalized before training.
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import logging

# TensorFlow and Keras for building the neural network
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

logger = logging.getLogger(__name__)


def get_anomalies_by_autoencoder(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect anomalies in log data using an Autoencoder model.

    This function trains an unsupervised autoencoder on normalized log features,
    then identifies anomalies based on reconstruction error thresholds.

    Args:
        df (pd.DataFrame): Input dataframe containing Zscaler NSS web log entries

    Returns:
        pd.DataFrame: Top 10 anomalous log entries with their reconstruction losses and metadata

    The function performs:
    1. Feature extraction from log fields
    2. Data normalization
    3. Autoencoder training on normal data
    4. Anomaly scoring based on reconstruction error
    5. Ranking and returning top anomalies
    """

    # Define the expected column names for Zscaler NSS web logs
    # These match the standard format from Zscaler documentation
    cols = ['time_gen','time_rec','action','rule','url','cat','user','src_ip','dst_ip',
            'src_port','dst_port','proto','method','status','bytes_sent','bytes_rec',
            'ua','ref','loc','dept','reason','req_id','app','threat','country',
            'threat_cat','file_type']

    # Extract and create numeric features suitable for anomaly detection
    # Focus on quantitative fields that can indicate unusual network behavior
    X = pd.DataFrame({
        "bytes_sent": df["bytes_sent"].astype(float),        # Bytes sent by client
        "bytes_rec": df["bytes_rec"].astype(float),          # Bytes received by client
        "status": df["status"].astype(int),                  # HTTP status code
        "src_port": df["src_port"].astype(int),              # Source port number
        "is_block": (df["action"] == "BLOCK").astype(int),   # Binary indicator for blocked requests
        "threat_score": df["threat"].map({                   # Numeric threat severity mapping
            "NONE": 0, "Phishing": 2, "Malware": 3, "Command-Control": 4
        }).fillna(0).astype(int),
    })

    # Normalize features to zero mean and unit variance for neural network training
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Split data into training and validation sets
    # Training set is used to train the autoencoder, validation for monitoring overfitting
    X_train, X_test = train_test_split(X_scaled, test_size=0.2, random_state=42)


    # Get the number of input features
    input_dim = X_train.shape[1]

    # Build the autoencoder architecture
    # Encoder: Compress input to lower-dimensional representation
    input_layer = keras.Input(shape=(input_dim,))
    encoded = layers.Dense(16, activation="relu")(input_layer)  # First encoding layer
    encoded = layers.Dense(8, activation="relu")(encoded)       # Bottleneck layer (latent space)

    # Decoder: Reconstruct input from encoded representation
    decoded = layers.Dense(16, activation="relu")(encoded)      # First decoding layer
    decoded = layers.Dense(input_dim, activation=None)(decoded) # Output layer (no activation for reconstruction)

    # Create and compile the autoencoder model
    autoencoder = keras.Model(inputs=input_layer, outputs=decoded)
    autoencoder.compile(optimizer="adam", loss="mse")  # Use Adam optimizer and mean squared error loss

    # Train the autoencoder model
    # The model learns to reconstruct its input, so target = input for unsupervised learning
    history = autoencoder.fit(
        X_train, X_train,                    # Input and target are the same for autoencoders
        epochs=30,                           # Number of training iterations
        batch_size=128,                      # Number of samples per gradient update
        validation_data=(X_test, X_test),    # Validation data for monitoring overfitting
        shuffle=True,                        # Shuffle training data each epoch
        verbose=1,                           # Show training progress
    )

    # Calculate reconstruction errors on training data to establish anomaly threshold
    recon_train = autoencoder.predict(X_train)
    train_loss = np.mean(np.square(recon_train - X_train), axis=1)  # MSE per sample
    threshold = np.percentile(train_loss, 99)   # Set threshold at 99th percentile (top 1% as anomalies)

    # Apply the trained model to the full dataset for anomaly detection
    recon_all = autoencoder.predict(X_scaled)
    all_loss = np.mean(np.square(recon_all - X_scaled), axis=1)  # Reconstruction error for each sample

    # Add anomaly scores and labels to the original dataframe
    df["ae_loss"] = all_loss
    df["ae_is_anomaly"] = df["ae_loss"] > threshold

    # Extract and return the top 10 most anomalous entries
    top = df.sort_values("ae_loss", ascending=False).head(10)
    result_df = top[["ae_loss","user","url","threat","bytes_rec","action","src_ip","dst_ip"]].copy()
    result_df['line'] = top.index + 1  # Add 1-based line number for reference
    logger.info(f"Autoencoder processed {len(df)} records, found {len(result_df)} anomalies with threshold {threshold}")
    logger.debug(f"Anomalies: {result_df.to_dict('records')}")
    return result_df

if __name__ == "__main__":
    # Example usage for testing the autoencoder anomaly detection
    # This demonstrates how to call the function with a sample log file
    # In practice, this would be called from the log_analyzer.py module
    test_file_path = "/Users/nallagonda/Kiran/tenex_project/micro_siem_backend/data/staging/admin_zscaler_nss_web_poc_1768194856996.log"
    result = get_anomalies_by_autoencoder(test_file_path)
    print("Autoencoder anomaly detection results:")
    print(result)
