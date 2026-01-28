# Phishing Detection & Response System

A production-ready, platform-independent GenAI-powered system for detecting and responding to phishing attempts across multiple channels.

## Features

- Multi-channel phishing detection (Email, SMS, WhatsApp, URLs)
- AI-powered risk assessment and scoring
- Human-readable explanations using GenAI
- Real-time analysis and response recommendations
- Web dashboard for interaction and monitoring

## Tech Stack

- **Backend**: Python 3.11, FastAPI, SQLAlchemy, Pydantic
- **Frontend**: React, Tailwind CSS, Vite
- **ML/DL**: scikit-learn, TensorFlow, Transformers
- **Database**: PostgreSQL, FAISS (for vector storage)
- **Deployment**: Docker, Docker Compose

## Getting Started

### Prerequisites

- Docker and Docker Compose
- Python 3.11+
- Node.js 18+

### Installation

1. Clone the repository
2. Set up environment variables (copy `.env.example` to `.env` and configure)
3. Run `docker-compose up --build`

## Project Structure

```
.
├── backend/               # Backend services
│   ├── api/              # FastAPI application
│   ├── ml/               # ML models and training
│   ├── genai/            # GenAI integration
│   ├── features/         # Feature extraction
│   ├── security/         # Auth and security utils
│   └── utils/            # Helper functions
├── frontend/             # React application
│   ├── public/           # Static files
│   └── src/              # React source code
├── docker/               # Docker configuration
└── docs/                 # Documentation
```

## License

MIT
