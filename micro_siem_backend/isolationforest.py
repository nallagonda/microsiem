from sklearn.ensemble import IsolationForest
from sklearn.preprocessing import StandardScaler
import pandas as pd
import numpy as np

def get_anomalies_by_isolationforest(df: pd.DataFrame) -> pd.DataFrame:
    # Parse your 10k log into features
    cols=['time_gen', 'time_rec', 'action', 'rule', 'url', 
                        'cat', 'user', 'src_ip', 'dst_ip', 'src_port', 
                        'dst_port', 'proto', 'method', 'status', 
                        'bytes_sent', 'bytes_rec', 'ua', 'ref', 
                        'loc', 'dept', 'reason', 'req_id', 'app', 
                        'threat', 'country', 'threat_cat', 'file_type']
    # Numeric features for anomaly detection
    features = df[['bytes_sent', 'bytes_rec', 'src_port']].copy()
    features['status_code'] = pd.to_numeric(df['status'])
    features['is_block'] = (df['action'] == 'BLOCK').astype(int)
    features['threat_score'] = df['threat'].map({'Malware':3, 'Phishing':2, 'Command-Control':3, 'NONE':0}).fillna(0)

    scaler = StandardScaler()
    X_scaled = scaler.fit_transform(features.fillna(0))

    # Train Isolation Forest (no labels needed)
    model = IsolationForest(contamination=0.1, random_state=42)
    anomalies = model.fit_predict(X_scaled)  # -1 = anomaly

    # Top anomalies
    df['anomaly_score'] = -model.decision_function(X_scaled)  # Negative for higher = more anomalous
    top = df.sort_values('anomaly_score', ascending=False).head(10)
    result_df = top[['user', 'url', 'threat', 'bytes_rec', 'anomaly_score', 'src_ip', 'dst_ip', 'action']].copy()
    result_df['line'] = top.index + 1  # 1-based line number
    print(result_df)
    return result_df

if __name__ == "__main__":
    cols=['time_gen', 'time_rec', 'action', 'rule', 'url',
                         'cat', 'user', 'src_ip', 'dst_ip', 'src_port',
                         'dst_port', 'proto', 'method', 'status',
                         'bytes_sent', 'bytes_rec', 'ua', 'ref',
                         'loc', 'dept', 'reason', 'req_id', 'app',
                         'threat', 'country', 'threat_cat', 'file_type']
    df = pd.read_csv("/Users/nallagonda/Kiran/tenex_project/micro_siem_backend/data/staging/admin_zscaler_nss_web_poc_1768194856996.log", sep='\t', header=None, names=cols)
    get_anomalies_by_isolationforest(df)
