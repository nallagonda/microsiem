"""
Variational Autoencoder (VAE) based Anomaly Detection Module

This module implements anomaly detection using a Variational Autoencoder neural network.
VAEs learn a probabilistic latent space representation of the data, making them effective
for generative modeling and anomaly detection.

Key advantages of VAE for anomaly detection:
- Probabilistic approach captures data distribution better than standard autoencoders
- Regularized latent space prevents overfitting
- Reconstruction probability can be used as anomaly score

The implementation includes:
- Custom VAE model class with encoder/decoder architecture
- Variational training with KL divergence regularization
- Anomaly scoring based on reconstruction error
"""

import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import logging
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

logger = logging.getLogger(__name__)

# Custom VAE model class that extends Keras Model
class VAE(keras.Model):
    """
    Custom Variational Autoencoder model extending Keras Model.

    This class combines encoder and decoder networks with variational training.
    It implements custom training loop with reconstruction and KL divergence losses.
    """
    def __init__(self, encoder, decoder, **kwargs):
        super().__init__(**kwargs)
        self.encoder = encoder  # Encoder network (inputs -> latent distribution parameters)
        self.decoder = decoder  # Decoder network (latent -> reconstruction)

        # Metrics to track training losses
        self.total_loss_tracker = keras.metrics.Mean(name="total_loss")
        self.recon_loss_tracker = keras.metrics.Mean(name="recon_loss")
        self.kl_loss_tracker = keras.metrics.Mean(name="kl_loss")

    @property
    def metrics(self):
        # Return metrics for Keras to reset after each epoch
        return [self.total_loss_tracker, self.recon_loss_tracker, self.kl_loss_tracker]

    def call(self, inputs):
        # Forward pass: encode input to latent space, then decode back to reconstruction
        z_mean, z_log_var, z = self.encoder(inputs)
        return self.decoder(z)

    def train_step(self, data):
        # Custom training step implementing variational loss
        # Handles both (x, y) tuple inputs and plain x inputs
        if isinstance(data, tuple):
            data = data[0]

        # Record operations for automatic differentiation
        with tf.GradientTape() as tape:
            # Encode input to latent distribution parameters
            z_mean, z_log_var, z = self.encoder(data)

            # Decode latent sample to reconstruction
            reconstruction = self.decoder(z)

            # Reconstruction loss: mean squared error between input and reconstruction
            recon_loss = tf.reduce_mean(tf.reduce_sum(tf.square(data - reconstruction), axis=1))

            # KL divergence loss: regularizes latent space to be close to standard normal
            # Formula: -0.5 * sum(1 + log_var - mean^2 - exp(log_var))
            kl_loss = -0.5 * tf.reduce_mean(
                tf.reduce_sum(1 + z_log_var - tf.square(z_mean) - tf.exp(z_log_var), axis=1)
            )

            # Total loss = reconstruction + KL divergence (beta = 1.0)
            total_loss = recon_loss + kl_loss

        # Compute gradients and update weights
        grads = tape.gradient(total_loss, self.trainable_weights)
        self.optimizer.apply_gradients(zip(grads, self.trainable_weights))

        # Update loss trackers
        self.total_loss_tracker.update_state(total_loss)
        self.recon_loss_tracker.update_state(recon_loss)
        self.kl_loss_tracker.update_state(kl_loss)

        # Return metrics for logging
        return {
            "loss": self.total_loss_tracker.result(),
            "recon_loss": self.recon_loss_tracker.result(),
            "kl_loss": self.kl_loss_tracker.result(),
        }


def get_anomalies_by_vae(df: pd.DataFrame) -> pd.DataFrame:
    """
    Detect anomalies in log data using a Variational Autoencoder.

    This function builds and trains a VAE on normalized log features,
    then identifies anomalies based on reconstruction error thresholds.

    Args:
        df (pd.DataFrame): Input dataframe containing Zscaler NSS web log entries

    Returns:
        pd.DataFrame: Top 10 anomalous log entries with reconstruction losses and metadata

    The VAE approach:
    1. Learns a probabilistic latent representation of normal network traffic
    2. Measures reconstruction quality for anomaly scoring
    3. Uses percentile-based thresholding for anomaly classification
    """

    # Define column structure for Zscaler logs
    cols = ['time_gen','time_rec','action','rule','url','cat','user','src_ip','dst_ip',
        'src_port','dst_port','proto','method','status','bytes_sent','bytes_rec',
        'ua','ref','loc','dept','reason','req_id','app','threat','country',
        'threat_cat','file_type']

    # Extract numeric features for VAE training
    # These features represent key aspects of network traffic patterns
    X = pd.DataFrame({
        "bytes_sent": df["bytes_sent"].astype(float),        # Client upload volume
        "bytes_rec": df["bytes_rec"].astype(float),          # Server response volume
        "status": df["status"].astype(int),                  # HTTP response code
        "src_port": df["src_port"].astype(int),              # Client port number
        "is_block": (df["action"] == "BLOCK").astype(int),   # Binary block indicator
        "threat_score": df["threat"].map({                   # Threat severity mapping
            "NONE": 0, "Phishing": 2, "Malware": 3, "Command-Control": 4
        }).fillna(0).astype(int),
    })

    # Normalize features for neural network training
    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    # Split into training and validation sets
    X_train, X_test = train_test_split(X_scaled, test_size=0.2, random_state=42)




    # Define latent space dimensionality (bottleneck size)
    latent_dim = 4
    input_dim = X_train.shape[1]

    # Build the Encoder network
    inputs = keras.Input(shape=(input_dim,))
    x = layers.Dense(16, activation="relu")(inputs)        # First encoding layer
    x = layers.Dense(8, activation="relu")(x)              # Second encoding layer

    # Latent distribution parameters (mean and log variance)
    z_mean = layers.Dense(latent_dim, name="z_mean")(x)
    z_log_var = layers.Dense(latent_dim, name="z_log_var")(x)

    # Reparameterization trick for sampling from latent distribution
    def sampling(args):
        z_mean, z_log_var = args
        # Sample epsilon from standard normal distribution
        epsilon = tf.random.normal(shape=(tf.shape(z_mean)[0], latent_dim))
        # Reparameterized sample: mean + std_dev * epsilon
        return z_mean + tf.exp(0.5 * z_log_var) * epsilon

    # Latent space sample using reparameterization
    z = layers.Lambda(sampling, output_shape=(latent_dim,), name="z")([z_mean, z_log_var])

    # Build the Decoder network (mirror of encoder)
    decoder_inputs = keras.Input(shape=(latent_dim,))
    dx = layers.Dense(8, activation="relu")(decoder_inputs)    # First decoding layer
    dx = layers.Dense(16, activation="relu")(dx)               # Second decoding layer
    outputs = layers.Dense(input_dim, activation=None)(dx)     # Output layer (no activation)

    # Create separate encoder and decoder models
    decoder = keras.Model(decoder_inputs, outputs, name="decoder")
    encoder = keras.Model(inputs, [z_mean, z_log_var, z], name="encoder")


    # Create VAE model combining encoder and decoder
    vae = VAE(encoder, decoder)

    # Compile with Adam optimizer; run_eagerly=True for custom training step compatibility
    vae.compile(optimizer=keras.optimizers.Adam(), run_eagerly=True)

    # Train the VAE on normal traffic patterns
    vae.fit(X_train, epochs=30, batch_size=128, shuffle=True)


    # Generate reconstructions for the entire dataset
    z_mean, z_log_var, z = encoder.predict(X_scaled)  # Encode all data to latent space
    recon = decoder.predict(z)                         # Decode back to original space

    # Calculate reconstruction error (mean squared error) for each sample
    recon_error = np.mean((X_scaled - recon) ** 2, axis=1)
    df["vae_loss"] = recon_error

    # Set anomaly threshold at 99th percentile of reconstruction errors
    # This assumes ~1% of training data represents anomalies
    threshold = np.percentile(recon_error, 99)
    df["vae_is_anomaly"] = df["vae_loss"] > threshold

    # Extract top 10 most anomalous entries based on reconstruction error
    top = df.sort_values("vae_loss", ascending=False).head(10)
    result_df = top[["vae_loss","user","url","threat","bytes_rec","action","src_ip","dst_ip"]].copy()
    result_df['line'] = top.index + 1  # Add 1-based line number for reference
    logger.info(f"VAE processed {len(df)} records, found {len(result_df)} anomalies with threshold {threshold}")
    logger.debug(f"Anomalies: {result_df.to_dict('records')}")
    return result_df

def test_vae():
    """Test function for VAE anomaly detection with sample data."""
    import pandas as pd

    # Define log format for testing
    cols = ['time_gen','time_rec','action','rule','url','cat','user','src_ip','dst_ip',
            'src_port','dst_port','proto','method','status','bytes_sent','bytes_rec',
            'ua','ref','loc','dept','reason','req_id','app','threat','country',
            'threat_cat','file_type']

    # Load a small sample for quick testing (first 100 rows)
    df = pd.read_csv("data/staging/admin_zscaler_nss_web_poc_1768194335492.log",
                     sep='\t', header=None, names=cols).head(100)
    result = get_anomalies_by_vae(df)
    print("Test VAE output:")
    print(result)
    return result

if __name__ == "__main__":
    # Run VAE testing when script is executed directly
    test_vae()
