# Micro SIEM Project

A micro Security Information and Event Management (SIEM) system that provides comprehensive log analysis capabilities using multiple machine learning techniques for anomaly detection and exploratory data analysis.

## Features

- **User Authentication**: JWT-based authentication with support for both username/password and Google OAuth
- **Log Upload**: Secure file upload with user-specific staging and analysis
- **Anomaly Detection**: Uses Isolation Forest, Autoencoder, and Variational Autoencoder (VAE) ML models
- **Exploratory Data Analysis**: Automatic generation of statistical graphs and visualizations
- **Real-time Analysis**: Background processing with status tracking and progress indicators
- **Web Interface**: React-based frontend with TypeScript for easy interaction
- **RESTful API**: Flask-based backend API with comprehensive endpoints
- **Docker Support**: Containerized deployment
- **Testing Suite**: Unit tests for all major components

## Tech Stack

- **Backend**: Python 3.12, Flask, Flask-CORS, Flask-JWT-Extended, Google Auth
- **Machine Learning**: scikit-learn, TensorFlow, pandas, numpy, matplotlib
- **Frontend**: React 19, TypeScript, Vite
- **Deployment**: Docker

## Installation

### Prerequisites

- Python 3.12.11 or higher
- Node.js 18+ and npm
- Docker (for containerized deployment)

### Backend Setup

1. Navigate to the backend directory:
   ```bash
   cd micro_siem_backend
   ```

2. Create and activate a virtual environment:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. Install Python dependencies:
   ```bash
   pip install -r requirements.txt
   ```

### Frontend Setup

1. Navigate to the frontend directory:
   ```bash
   cd micro_siem_ui/siem_ui
   ```

2. Install Node.js dependencies:
   ```bash
   npm install
   ```

3. Build the frontend:
   ```bash
   npm run build
   ```

## Running the Application

### Development Mode

1. Start the backend:
   ```bash
   cd micro_siem_backend
   python app.py
   ```
   The backend will run on http://localhost:5000

2. Start the frontend (in a separate terminal):
   ```bash
   cd micro_siem_ui/siem_ui
   npm run dev
   ```
   The frontend will run on http://localhost:5173 (default Vite port)

### Production Mode

The Flask backend is configured to serve the built frontend static files. After building the frontend, run the backend and access the full application at http://localhost:5000

## Docker Deployment

1. Ensure the frontend is built (run `npm run build` in micro_siem_ui/siem_ui)

2. Build the Docker image from the project root:
   ```bash
   docker build -t micro-siem .
   ```

3. Run the container:
   ```bash
   docker run -p 5000:5000 micro-siem
   ```

4. Access the application at http://localhost:5000

## API Endpoints

### Authentication
- `POST /login` - User login
  - Body: `{"username": "admin", "password": "password123"}`
  - Returns: JWT access token

- `POST /google_login` - Google OAuth login
  - Body: `{"token": "google_jwt_token"}`
  - Returns: JWT access token

### File Operations
- `POST /upload` - Upload log file (requires JWT)
  - Headers: `Authorization: Bearer <token>`
  - Form data: `file` (log file)
  - Returns: Upload confirmation with file ID

- `GET /analysis/<file_id>` - Get analysis results (requires JWT)
  - Headers: `Authorization: Bearer <token>`
  - Returns: JSON analysis data with anomalies and graphs

- `GET /analysis_file/<filename>` - Serve analysis graphs
  - Returns: PNG image files

## Usage

1. **Login**: Use username/password (default: admin/password123) or Google OAuth
2. **Upload Logs**: Select and upload log files through the web interface
3. **View Analysis**: Monitor processing with progress indicator, then view anomaly detection results and EDA graphs
4. **Analysis Results**: Includes anomalies from multiple ML models and data visualizations

## Project Structure

```
tenex_project/
├── micro_siem_backend/
│   ├── app.py                 # Main Flask application with API endpoints
│   ├── log_analyzer.py        # Log analysis and EDA graph generation
│   ├── isolationforest.py     # Isolation Forest anomaly detection
│   ├── autoencoder.py         # Autoencoder anomaly detection
│   ├── vae.py                 # Variational Autoencoder anomaly detection
│   ├── log_synthesizer.py     # Log generation for testing
│   ├── requirements.txt       # Python dependencies
│   ├── .env                   # Environment variables
│   └── data/                  # Data storage and staging
├── micro_siem_ui/
│   └── siem_ui/               # React frontend
│       ├── src/
│       │   ├── App.tsx
│       │   ├── Login.tsx
│       │   ├── FileUpload.tsx
│       │   ├── Analysis.tsx
│       │   └── ...
│       ├── dist/              # Built frontend (after npm run build)
│       └── package.json
├── Dockerfile                 # Docker configuration
└── README.md                  # This file
```

## Configuration

- JWT Secret: Modify `app.config["JWT_SECRET_KEY"]` in `app.py` for production
- Google OAuth: Set `GOOGLE_CLIENT_ID` in `micro_siem_backend/.env` and `VITE_GOOGLE_CLIENT_ID` in `micro_siem_ui/siem_ui/.env`
- User Credentials: Update `USERS` dict in `app.py`
- ML Models: Adjust parameters in `isolationforest.py`, `autoencoder.py`, and `vae.py`

## Log Data Generation

The project includes a synthetic log generator (`micro_siem_backend/data/log_synthesizer.py`) for testing and demonstration purposes. This tool generates realistic Zscaler NSS Web log entries with the following features:

- **Realistic Data**: Creates log entries matching the standard Zscaler NSS Web format with 27 fields
- **Sample Users and Departments**: Includes predefined users (jdoe@example.com, asmith@corp.com, etc.) and departments
- **Varied Actions**: Generates ALLOW, BLOCK, and ALERT actions with appropriate rules
- **Threat Simulation**: Includes various threat types (NONE, Malware, Phishing, Command-Control)
- **Geographic Diversity**: Randomly assigns countries and locations
- **Temporal Distribution**: Spreads events across time periods

### Usage

Run the synthesizer to generate test logs:
```bash
cd micro_siem_backend/data
python log_synthesizer.py
```

This creates `zscaler_nss_web_poc.log` with 10,000 sample entries and prints summary statistics including top blocked users and suspicious activities.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Test thoroughly
5. Submit a pull request

## SOC Analyst Investigation Guide

When reviewing the surfaced anomalous log entries, focus on these key investigation steps:

**User Analysis**: Examine other sessions from the same user within similar timeframes. Look for sudden spikes in activity volume, access to unusual destinations, or deviations from normal behavioral patterns.

**URL/Domain/IP Investigation**: Perform reputation checks on flagged URLs, domains, or IP addresses. Cross-reference with threat intelligence feeds, conduct reverse DNS lookups, and verify geographical locations.

**Contextual Assessment**: Evaluate the timing (time of day, day of week), device information, department affiliation, and whether the observed behavior represents a new pattern for that user account.

**Anomaly Scoring Details**: The system uses multiple ML models with different contamination thresholds:
- Isolation Forest: contamination=0.1, scores based on decision function
- Autoencoder: 99th percentile reconstruction error threshold
- VAE: 99th percentile reconstruction error threshold

Understanding these scoring mechanisms helps explain why specific entries were flagged as anomalous.