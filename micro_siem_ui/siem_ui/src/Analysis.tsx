
import { useEffect, useState } from 'react';
import './Analysis.css';

interface AnomaliesProps {
  onBack: () => void;
  token: string;
  fileId: string;
}

function Anomalies({ onBack, token, fileId }: AnomaliesProps) {
  const [anomalies, setAnomalies] = useState<{isolationforest: any[], autoencoder: any[], vae: any[]}>({isolationforest: [], autoencoder: [], vae: []});
  const [data, setData] = useState<any>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    const fetchAnalysis = async () => {
      try {
        const response = await fetch(`http://localhost:5000/analysis/${fileId}`, {
          headers: {
            'Authorization': `Bearer ${token}`,
          },
        });
        if (response.ok) {
          const data = await response.json();
          if (data.anomalies) {
            setAnomalies(data.anomalies);
            setData(data);
            setLoading(false);
          } else {
            // Still processing, poll again
            setTimeout(fetchAnalysis, 2000);
          }
        } else {
          setLoading(false);
        }
      } catch (error) {
        setLoading(false);
      }
    };

    fetchAnalysis();
  }, [token, fileId]);

  return (
    <div style={{ position: 'relative', minHeight: '100vh', padding: '20px' }}>
      <button onClick={onBack} style={{ position: 'absolute', top: '20px', right: '20px' }}>Back</button>
      <h1>Here are the Analysis Details</h1>
      {loading ? (
        <div style={{ textAlign: 'center', padding: '50px' }}>
          <div className="spinner"></div>
          <p>Analysis in progress...</p>
        </div>
      ) : (
        <>
          <p>Log analysis complete. Here are the detected anomalies:</p>
          {Object.keys(anomalies).map(model => (
            <div key={model}>
              <h2>{model.charAt(0).toUpperCase() + model.slice(1)} Anomalies</h2>
              <ul style={{ listStyle: 'none', padding: 0 }}>
                {anomalies[model as keyof typeof anomalies].length > 0 ? (
                  anomalies[model as keyof typeof anomalies].map((anom: any, index: number) => {

                    return (
                      <li key={index} className={`threat-color-${anom.threat.toLowerCase().replace('-', '-')}`} style={{ marginBottom: '10px', padding: '10px', border: '1px solid', borderRadius: '5px' }}>
                        <strong>Line:</strong> {anom.line} | <strong>User:</strong> {anom.user} | <strong>URL:</strong> {anom.url} | <strong>Threat:</strong> {anom.threat} | <strong>Bytes Received:</strong> {anom.bytes_rec} | <strong>Source IP:</strong> {anom.src_ip} | <strong>Destination IP:</strong> {anom.dst_ip} | <strong>Action:</strong> {anom.action} | <strong>{model === 'autoencoder' ? 'ae_loss' : model === 'vae' ? 'vae_loss' : 'anomaly_score'}:</strong> {(model === 'autoencoder' ? anom.ae_loss : model === 'vae' ? anom.vae_loss : anom.anomaly_score)?.toFixed(4) || 'N/A'}
                      </li>
                    );
                  })
                ) : (
                  <li>No anomalies detected.</li>
                )}
              </ul>
            </div>
          ))}
          {data && data.graphs && (
            <>
              <h1>Exploratory Data Analysis</h1>
              {data.graphs.map((graph: string, index: number) => (
                <div key={index} style={{ marginBottom: '20px' }}>
                  <img src={`http://localhost:5000/analysis_file/${fileId.replace('.log', '_' + graph)}`} alt={`EDA Graph ${index + 1}`} style={{ maxWidth: '100%', height: 'auto' }} />
                </div>
              ))}
            </>
          )}
        </>
      )}
    </div>
  );
}

export default Anomalies;