import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split
import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers

# VAE model with custom loss
class VAE(keras.Model):
    def __init__(self, encoder, decoder, **kwargs):
        super().__init__(**kwargs)
        self.encoder = encoder
        self.decoder = decoder
        self.total_loss_tracker = keras.metrics.Mean(name="total_loss")
        self.recon_loss_tracker = keras.metrics.Mean(name="recon_loss")
        self.kl_loss_tracker = keras.metrics.Mean(name="kl_loss")

    @property
    def metrics(self):
        return [self.total_loss_tracker, self.recon_loss_tracker, self.kl_loss_tracker]

    def call(self, inputs):
        z_mean, z_log_var, z = self.encoder(inputs)
        return self.decoder(z)

    def train_step(self, data):
        if isinstance(data, tuple):
            data = data[0]
        with tf.GradientTape() as tape:
            z_mean, z_log_var, z = self.encoder(data)
            reconstruction = self.decoder(z)
            recon_loss = tf.reduce_mean(tf.reduce_sum(tf.square(data - reconstruction), axis=1))
            kl_loss = -0.5 * tf.reduce_mean(
                tf.reduce_sum(1 + z_log_var - tf.square(z_mean) - tf.exp(z_log_var), axis=1)
            )
            total_loss = recon_loss + kl_loss
        grads = tape.gradient(total_loss, self.trainable_weights)
        self.optimizer.apply_gradients(zip(grads, self.trainable_weights))
        self.total_loss_tracker.update_state(total_loss)
        self.recon_loss_tracker.update_state(recon_loss)
        self.kl_loss_tracker.update_state(kl_loss)
        return {
            "loss": self.total_loss_tracker.result(),
            "recon_loss": self.recon_loss_tracker.result(),
            "kl_loss": self.kl_loss_tracker.result(),
        }


def get_anomalies_by_vae(df: pd.DataFrame) -> pd.DataFrame:

    cols = ['time_gen','time_rec','action','rule','url','cat','user','src_ip','dst_ip',
        'src_port','dst_port','proto','method','status','bytes_sent','bytes_rec',
        'ua','ref','loc','dept','reason','req_id','app','threat','country',
        'threat_cat','file_type']

    X = pd.DataFrame({
        "bytes_sent": df["bytes_sent"].astype(float),
        "bytes_rec": df["bytes_rec"].astype(float),
        "status": df["status"].astype(int),
        "src_port": df["src_port"].astype(int),
        "is_block": (df["action"] == "BLOCK").astype(int),
        "threat_score": df["threat"].map({
            "NONE": 0, "Phishing": 2, "Malware": 3, "Command-Control": 4
        }).fillna(0).astype(int),
    })

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(X)

    X_train, X_test = train_test_split(X_scaled, test_size=0.2, random_state=42)




    latent_dim = 4
    input_dim = X_train.shape[1]

    # Encoder
    inputs = keras.Input(shape=(input_dim,))
    x = layers.Dense(16, activation="relu")(inputs)
    x = layers.Dense(8, activation="relu")(x)
    z_mean = layers.Dense(latent_dim, name="z_mean")(x)
    z_log_var = layers.Dense(latent_dim, name="z_log_var")(x)

    def sampling(args):
        z_mean, z_log_var = args
        epsilon = tf.random.normal(shape=(tf.shape(z_mean)[0], latent_dim))
        return z_mean + tf.exp(0.5 * z_log_var) * epsilon

    z = layers.Lambda(sampling, output_shape=(latent_dim,), name="z")([z_mean, z_log_var])

    # Decoder
    decoder_inputs = keras.Input(shape=(latent_dim,))
    dx = layers.Dense(8, activation="relu")(decoder_inputs)
    dx = layers.Dense(16, activation="relu")(dx)
    outputs = layers.Dense(input_dim, activation=None)(dx)

    decoder = keras.Model(decoder_inputs, outputs, name="decoder")
    encoder = keras.Model(inputs, [z_mean, z_log_var, z], name="encoder")


    vae = VAE(encoder, decoder)
    vae.compile(optimizer=keras.optimizers.Adam(), run_eagerly=True)
    vae.fit(X_train, epochs=30, batch_size=128, shuffle=True)


    # Reconstruction on full dataset
    z_mean, z_log_var, z = encoder.predict(X_scaled)
    recon = decoder.predict(z)

    recon_error = np.mean((X_scaled - recon) ** 2, axis=1)
    df["vae_loss"] = recon_error

    # Threshold: use e.g. 99th percentile
    threshold = np.percentile(recon_error, 99)
    df["vae_is_anomaly"] = df["vae_loss"] > threshold

    top = df.sort_values("vae_loss", ascending=False).head(10)
    result_df = top[["vae_loss","user","url","threat","bytes_rec","action","src_ip","dst_ip"]].copy()
    result_df['line'] = top.index + 1  # 1-based line number
    print("Threshold:", threshold)
    print(result_df)
    return result_df

def test_vae():
    """Test method for VAE anomaly detection."""
    import pandas as pd
    cols = ['time_gen','time_rec','action','rule','url','cat','user','src_ip','dst_ip',
            'src_port','dst_port','proto','method','status','bytes_sent','bytes_rec',
            'ua','ref','loc','dept','reason','req_id','app','threat','country',
            'threat_cat','file_type']
    df = pd.read_csv("data/staging/admin_zscaler_nss_web_poc_1768194335492.log", sep='\t', header=None, names=cols).head(100)  # Use first 100 rows for testing
    result = get_anomalies_by_vae(df)
    print("Test VAE output:")
    print(result)
    return result

if __name__ == "__main__":
    test_vae()
