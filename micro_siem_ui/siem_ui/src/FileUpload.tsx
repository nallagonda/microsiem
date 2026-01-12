import { useState } from 'react';

const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000';

interface FileUploadProps {
  onLogout: () => void;
  token: string;
  onUploadSuccess: (fileId: string) => void;
  user: string;
}

function FileUpload({ onLogout, token, onUploadSuccess, user }: FileUploadProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [uploadStatus, setUploadStatus] = useState('');
  const [isDragOver, setIsDragOver] = useState(false);

  const validateFile = (file: File) => {
    return file.name.toLowerCase().endsWith('.log');
  };

  const handleFileChange = (event: React.ChangeEvent<HTMLInputElement>) => {
    if (event.target.files && event.target.files[0]) {
      const file = event.target.files[0];
      if (validateFile(file)) {
        setSelectedFile(file);
        setUploadStatus('');
      } else {
        setUploadStatus('Only .log files are allowed.');
        setSelectedFile(null);
      }
    }
  };

  const handleDragOver = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragOver(true);
  };

  const handleDragLeave = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragOver(false);
  };

  const handleDrop = (event: React.DragEvent<HTMLDivElement>) => {
    event.preventDefault();
    setIsDragOver(false);
    if (event.dataTransfer.files && event.dataTransfer.files[0]) {
      const file = event.dataTransfer.files[0];
      if (validateFile(file)) {
        setSelectedFile(file);
        setUploadStatus('');
      } else {
        setUploadStatus('Only .log files are allowed.');
        setSelectedFile(null);
      }
    }
  };

  const handleUpload = async () => {
    if (!selectedFile) {
      setUploadStatus('Please select a file first.');
      return;
    }

    const formData = new FormData();
    formData.append('file', selectedFile);

    try {
      const response = await fetch(`${API_BASE_URL}/upload`, {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${token}`,
        },
        body: formData,
      });

      if (response.ok) {
        const data = await response.json();
        setUploadStatus('File uploaded successfully!');
        onUploadSuccess(data.file_id);
      } else {
        setUploadStatus('Upload failed.');
      }
    } catch (error) {
      setUploadStatus('Upload error.');
    }
  };

  return (
    <div style={{ position: 'relative', minHeight: '100vh', padding: '20px' }}>
      <button onClick={onLogout} style={{ position: 'absolute', top: '20px', right: '20px' }}>Logout</button>
      <h1>Welcome, {user}!! </h1>
      <h2>Please upload log file, to identify anomalies!</h2>
      <p>Only .log files are accepted. You can select a file or drag and drop it below.</p>
      <div
        onDragOver={handleDragOver}
        onDragLeave={handleDragLeave}
        onDrop={handleDrop}
        style={{
          border: `2px dashed ${isDragOver ? 'blue' : 'gray'}`,
          borderRadius: '5px',
          padding: '20px',
          textAlign: 'center',
          marginBottom: '10px',
          backgroundColor: isDragOver ? '#f0f8ff' : 'transparent',
        }}
      >
        {selectedFile ? `Selected: ${selectedFile.name}` : 'Drag and drop a .log file here or click to select'}
        <br />
        <input
          type="file"
          accept=".log"
          onChange={handleFileChange}
          style={{ marginTop: '10px' }}
        />
      </div>
      <button onClick={handleUpload} disabled={!selectedFile}>Upload</button>
      <p>{uploadStatus}</p>
    </div>
  );
}

export default FileUpload;