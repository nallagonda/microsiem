import pandas as pd
import numpy as np
from sklearn.preprocessing import StandardScaler
from sklearn.model_selection import train_test_split

import tensorflow as tf
from tensorflow import keras
from tensorflow.keras import layers


def get_anomalies_by_autoencoder(df: pd.DataFrame) -> pd.DataFrame:

    # Load synthesized Zscaler log
    cols = ['time_gen','time_rec','action','rule','url','cat','user','src_ip','dst_ip',
            'src_port','dst_port','proto','method','status','bytes_sent','bytes_rec',
            'ua','ref','loc','dept','reason','req_id','app','threat','country',
            'threat_cat','file_type']

    # Simple numeric feature set (extend as needed)
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


    input_dim = X_train.shape[1]

    input_layer = keras.Input(shape=(input_dim,))
    encoded = layers.Dense(16, activation="relu")(input_layer)
    encoded = layers.Dense(8, activation="relu")(encoded)

    decoded = layers.Dense(16, activation="relu")(encoded)
    decoded = layers.Dense(input_dim, activation=None)(decoded)

    autoencoder = keras.Model(inputs=input_layer, outputs=decoded)
    autoencoder.compile(optimizer="adam", loss="mse")

    history = autoencoder.fit(
        X_train, X_train,
        epochs=30,
        batch_size=128,
        validation_data=(X_test, X_test),
        shuffle=True,
        verbose=1,
    )

    # Reconstruction errors on training data → threshold
    recon_train = autoencoder.predict(X_train)
    train_loss = np.mean(np.square(recon_train - X_train), axis=1)
    threshold = np.percentile(train_loss, 99)   # top 1% as anomalies

    # Apply to full dataset
    recon_all = autoencoder.predict(X_scaled)
    all_loss = np.mean(np.square(recon_all - X_scaled), axis=1)

    df["ae_loss"] = all_loss
    df["ae_is_anomaly"] = df["ae_loss"] > threshold

    # Show top N anomalies
    top = df.sort_values("ae_loss", ascending=False).head(10)
    result_df = top[["ae_loss","user","url","threat","bytes_rec","action","src_ip","dst_ip"]].copy()
    result_df['line'] = top.index + 1  # 1-based line number
    print(result_df)
    print("Threshold:", threshold)
    return result_df

if __name__ == "__main__":
    get_anomalies_by_autoencoder("/Users/nallagonda/Kiran/tenex_project/micro_siem_backend/data/staging/admin_zscaler_nss_web_poc_1768194856996.log")
