# Secure API Key Storage Dashboard

A modern web dashboard for managing API keys with enterprise-grade security.

## Features

- 🔐 **Secure Authentication** - JWT-based auth with refresh tokens
- 🎨 **Modern UI** - Built with Next.js 14, TypeScript, and Tailwind CSS
- 📊 **Analytics Dashboard** - Real-time statistics and visualizations
- 🔑 **Key Management** - Full CRUD operations for API keys
- 📝 **Audit Logging** - Complete activity tracking with real-time updates
- 🔄 **Key Rotation** - Automated and manual key rotation
- 🌐 **Service Integration** - Support for GitHub, Claude, AWS, and more
- 📱 **Responsive Design** - Works on desktop and mobile devices

## Tech Stack

### Backend (FastAPI)
- FastAPI for high-performance REST API
- JWT authentication with refresh tokens
- WebSocket support for real-time updates
- SQLite for metadata storage
- Comprehensive security middleware

### Frontend (Next.js)
- Next.js 14 with App Router
- TypeScript for type safety
- Tailwind CSS for styling
- React Query for data fetching
- Recharts for visualizations
- Lucide React for icons

## Quick Start

### Prerequisites
- Python 3.8+
- Node.js 16+
- Master password set in environment

### Backend Setup

```bash
cd dashboard/backend

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install dependencies
pip install -r requirements.txt

# Copy environment file
cp .env.example .env

# Edit .env and set your master password
# API_KEY_MASTER=your-secure-master-password

# Start the backend
./start.sh
# Or manually: uvicorn main:app --reload
```

The backend will be available at http://localhost:8000
API documentation at http://localhost:8000/docs

### Frontend Setup

```bash
cd dashboard/frontend

# Install dependencies
npm install

# Start development server
npm run dev
```

The frontend will be available at http://localhost:3000

## Architecture

```
┌─────────────────────────────────────────────────┐
│                Browser (Next.js)                 │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐   │
│  │   Auth   │ │   Keys   │ │  Analytics   │   │
│  │  Pages   │ │ Manager  │ │  Dashboard   │   │
│  └──────────┘ └──────────┘ └──────────────┘   │
└────────────────────┬───────────────────────────┘
                     │ HTTPS + JWT
┌────────────────────┴───────────────────────────┐
│               FastAPI Backend                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────────┐  │
│  │   Auth   │ │   API    │ │  WebSocket   │  │
│  │ Endpoints│ │ Routes   │ │   Server     │  │
│  └──────────┘ └──────────┘ └──────────────┘  │
└────────────────────┬───────────────────────────┘
                     │
┌────────────────────┴───────────────────────────┐
│          Secure Storage (Python)                │
│         AES-256-GCM Encryption                  │
└─────────────────────────────────────────────────┘
```

## Security Features

- **Authentication**: JWT tokens with 15-minute expiry and refresh tokens
- **Authorization**: Role-based access control
- **Encryption**: All API keys encrypted with AES-256-GCM
- **Security Headers**: CSP, HSTS, X-Frame-Options, etc.
- **Rate Limiting**: 100 requests per minute per IP
- **CSRF Protection**: Token-based CSRF protection
- **Audit Logging**: All operations logged with timestamps

## Available Pages

1. **Login** (`/login`) - Master password authentication
2. **Dashboard** (`/`) - Overview and analytics
3. **Keys** (`/keys`) - API key management
4. **Audit Logs** (`/audit`) - Activity tracking
5. **Settings** (`/settings`) - Configuration

## Development

### Backend Development

```bash
# Run with auto-reload
uvicorn main:app --reload --host 0.0.0.0 --port 8000

# Run tests
pytest

# Format code
black .
```

### Frontend Development

```bash
# Development server
npm run dev

# Build for production
npm run build

# Start production server
npm start

# Run linting
npm run lint
```

## Production Deployment

### Using Docker

```bash
# Build images
docker-compose build

# Start services
docker-compose up -d
```

### Manual Deployment

1. Set production environment variables
2. Use a production WSGI server (Gunicorn) for backend
3. Build and deploy Next.js frontend
4. Configure reverse proxy (Nginx)
5. Enable HTTPS with SSL certificates

## Environment Variables

### Backend (.env)
```env
API_KEY_MASTER=your-secure-master-password
JWT_SECRET_KEY=your-jwt-secret-key
DATABASE_URL=sqlite+aiosqlite:///./dashboard.db
CORS_ORIGINS=http://localhost:3000
```

### Frontend (.env.local)
```env
NEXT_PUBLIC_API_URL=http://localhost:8000
```

## API Documentation

The backend provides automatic API documentation via FastAPI:
- Swagger UI: http://localhost:8000/docs
- ReDoc: http://localhost:8000/redoc

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Run tests
5. Submit a pull request

## License

MIT License - see LICENSE file for details