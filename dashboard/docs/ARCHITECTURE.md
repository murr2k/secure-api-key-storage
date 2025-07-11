# Dashboard Architecture

## Overview

The Secure API Key Storage Dashboard provides a modern web interface for managing API keys with enterprise-grade security.

## Tech Stack

### Backend
- **FastAPI** - Modern Python web framework with automatic OpenAPI docs
- **SQLite** - Encrypted database for metadata (keys remain in secure storage)
- **JWT** - Secure session management
- **WebSockets** - Real-time audit log updates

### Frontend
- **Next.js 14** - React framework with App Router
- **TypeScript** - Type safety
- **Tailwind CSS** - Modern styling
- **shadcn/ui** - Beautiful UI components
- **React Query** - Data fetching and caching
- **Chart.js** - Analytics and visualizations

## Architecture Diagram

```
┌─────────────────────────────────────────────────────────┐
│                    Browser (Client)                      │
│  ┌─────────────────────────────────────────────────┐   │
│  │            Next.js Dashboard (React)             │   │
│  │  ┌──────────┐ ┌──────────┐ ┌──────────────┐   │   │
│  │  │   Auth   │ │   Keys   │ │  Audit Logs  │   │   │
│  │  │  Module  │ │ Manager  │ │    Viewer    │   │   │
│  │  └──────────┘ └──────────┘ └──────────────┘   │   │
│  └─────────────────────────────────────────────────┘   │
└────────────────────────┬───────────────────────────────┘
                         │ HTTPS + JWT
┌────────────────────────┴───────────────────────────────┐
│                 FastAPI Backend (API)                   │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐  │
│  │   Auth   │ │   Keys   │ │  Audit   │ │Analytics│  │
│  │ Endpoint │ │ Endpoint │ │ Endpoint │ │Endpoint │  │
│  └──────────┘ └──────────┘ └──────────┘ └─────────┘  │
│         │            │             │           │        │
│  ┌──────┴───────────┴─────────────┴───────────┴────┐  │
│  │            SecureKeyStorage (Core)               │  │
│  │     (Existing Python Implementation)             │  │
│  └──────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────┘
                         │
┌─────────────────────────┴───────────────────────────────┐
│                 Encrypted Storage                        │
│  ┌──────────────┐ ┌──────────────┐ ┌──────────────┐   │
│  │  API Keys    │ │ Audit Logs   │ │   Metadata   │   │
│  │  (AES-256)   │ │   (JSON)     │ │   (SQLite)   │   │
│  └──────────────┘ └──────────────┘ └──────────────┘   │
└─────────────────────────────────────────────────────────┘
```

## Security Features

1. **Authentication**
   - JWT tokens with 15-minute expiry
   - Refresh tokens with secure HttpOnly cookies
   - Optional 2FA support

2. **Authorization**
   - Role-based access control (Admin, User, ReadOnly)
   - Per-key permissions
   - API rate limiting

3. **Transport Security**
   - HTTPS enforced
   - CORS configured for frontend origin only
   - Security headers (CSP, HSTS, etc.)

4. **Data Security**
   - Keys never sent to frontend (only metadata)
   - Copy-to-clipboard uses secure API
   - Audit logging for all operations

## API Endpoints

### Authentication
- `POST /api/auth/login` - Login with master password
- `POST /api/auth/logout` - Logout and invalidate tokens
- `POST /api/auth/refresh` - Refresh access token
- `GET /api/auth/session` - Get current session info

### Key Management
- `GET /api/keys` - List all keys (metadata only)
- `POST /api/keys` - Create new key
- `GET /api/keys/{id}` - Get key details
- `PUT /api/keys/{id}` - Update key
- `DELETE /api/keys/{id}` - Delete key
- `POST /api/keys/{id}/rotate` - Rotate key
- `POST /api/keys/{id}/copy` - Copy key to clipboard

### Audit Logs
- `GET /api/audit` - Get audit logs with pagination
- `GET /api/audit/export` - Export audit logs
- `WS /api/audit/stream` - Real-time audit stream

### Analytics
- `GET /api/analytics/overview` - Dashboard statistics
- `GET /api/analytics/usage` - Key usage metrics
- `GET /api/analytics/security` - Security events

## Frontend Pages

1. **Login** (`/login`)
   - Master password entry
   - Remember me option
   - 2FA if enabled

2. **Dashboard** (`/`)
   - Overview statistics
   - Recent activity
   - Quick actions

3. **Keys** (`/keys`)
   - List all keys with search/filter
   - Add/Edit/Delete keys
   - Bulk operations

4. **Key Details** (`/keys/:id`)
   - Key information
   - Usage history
   - Rotation schedule
   - Permissions

5. **Audit Logs** (`/audit`)
   - Filterable log viewer
   - Export functionality
   - Real-time updates

6. **Settings** (`/settings`)
   - Security settings
   - Rotation policies
   - User preferences

## Development Workflow

1. **Backend Setup**
   ```bash
   cd dashboard/backend
   python -m venv venv
   source venv/bin/activate
   pip install -r requirements.txt
   uvicorn main:app --reload
   ```

2. **Frontend Setup**
   ```bash
   cd dashboard/frontend
   npm install
   npm run dev
   ```

3. **Production Build**
   ```bash
   # Backend
   uvicorn main:app --host 0.0.0.0 --port 8000

   # Frontend
   npm run build
   npm start
   ```

## Deployment Options

1. **Docker Compose** - Single command deployment
2. **Kubernetes** - Scalable with Helm charts
3. **Cloud Platforms** - Vercel (frontend) + Cloud Run (backend)
4. **Self-hosted** - Nginx reverse proxy setup