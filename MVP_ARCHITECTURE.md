# TriageOps MVP Architecture & Implementation Roadmap

## 1. MVP Scope Definition

### Retained Technologies
- **Backend**: FastAPI (Python 3.12+)
- **Frontend**: React 18+ + TypeScript
- **Database**: PostgreSQL 16+
- **Caching**: Redis 7+
- **Containerization**: Docker + Docker Compose
- **AI**: LangChain + OpenAI GPT-4o-mini / Claude 3.5 Haiku
- **Architecture**: Modular Monolith

### Removed for MVP
- Kubernetes
- Microservices
- API Gateway
- Elasticsearch
- TimescaleDB
- Complex MLOps (MLflow, etc.)

---

## 2. MVP System Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                      Client Layer                           │
│  ┌──────────────────────────────────────────────────────┐  │
│  │              React + TypeScript Frontend             │  │
│  │  - Dashboard  - Alert Queue  - Incident View        │  │
│  │  - SOC Console  - Admin Panel                       │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │ HTTPS / WebSockets
                            ▼
┌─────────────────────────────────────────────────────────────┐
│              FastAPI Modular Monolith Backend               │
│  ┌──────────────────────────────────────────────────────┐  │
│  │  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐ │  │
│  │  │     API      │  │   Services   │  │   Workers    │ │  │
│  │  │   (FastAPI)  │  │   (Modules)  │  │  (Celery)    │ │  │
│  │  └──────────────┘  └──────────────┘  └──────────────┘ │  │
│  └──────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                       Data Layer                            │
│  ┌──────────────────┐  ┌────────────────────────────────┐  │
│  │   PostgreSQL     │  │            Redis               │  │
│  │  (Primary DB)    │  │  (Cache, Sessions, Broker)     │  │
│  └──────────────────┘  └────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────┘
```

---

## 3. MVP Folder Structure

```
triageops/
├── backend/
│   ├── src/
│   │   ├── api/
│   │   │   ├── v1/
│   │   │   │   ├── __init__.py
│   │   │   │   ├── auth.py
│   │   │   │   ├── users.py
│   │   │   │   ├── alerts.py
│   │   │   │   ├── incidents.py
│   │   │   │   ├── risk.py
│   │   │   │   ├── ai.py
│   │   │   │   ├── threat_intel.py
│   │   │   │   ├── feedback.py
│   │   │   │   └── dashboard.py
│   │   │   └── deps.py
│   │   ├── core/
│   │   │   ├── __init__.py
│   │   │   ├── config.py
│   │   │   ├── security.py
│   │   │   ├── logging.py
│   │   │   └── database.py
│   │   ├── models/
│   │   │   ├── __init__.py
│   │   │   ├── sqlalchemy.py
│   │   │   ├── pydantic.py
│   │   │   └── ocsf.py
│   │   ├── services/
│   │   │   ├── __init__.py
│   │   │   ├── auth_service.py
│   │   │   ├── user_service.py
│   │   │   ├── alert_service.py
│   │   │   ├── incident_service.py
│   │   │   ├── risk_service.py
│   │   │   ├── ai_service.py
│   │   │   ├── threat_intel_service.py
│   │   │   └── feedback_service.py
│   │   ├── workers/
│   │   │   ├── __init__.py
│   │   │   ├── celery_app.py
│   │   │   └── tasks.py
│   │   ├── utils/
│   │   │   ├── __init__.py
│   │   │   └── ocsf_normalizer.py
│   │   └── main.py
│   ├── tests/
│   │   ├── __init__.py
│   │   ├── unit/
│   │   └── integration/
│   ├── alembic/
│   ├── .env.example
│   ├── Dockerfile
│   └── requirements.txt
├── frontend/
│   ├── public/
│   ├── src/
│   │   ├── components/
│   │   │   ├── common/
│   │   │   ├── dashboard/
│   │   │   ├── alerts/
│   │   │   ├── incidents/
│   │   │   ├── auth/
│   │   │   └── admin/
│   │   ├── pages/
│   │   ├── services/
│   │   ├── store/
│   │   ├── utils/
│   │   ├── types/
│   │   ├── App.tsx
│   │   └── main.tsx
│   ├── .env.example
│   ├── Dockerfile
│   ├── package.json
│   └── tsconfig.json
├── docker/
│   ├── docker-compose.yml
│   └── nginx.conf
├── MVP_ARCHITECTURE.md
└── README.md
```

---

## 4. MVP Database Schema (PostgreSQL)

### Core Tables

**tenants**
- id (UUID, PK)
- name (VARCHAR)
- slug (VARCHAR, UNIQUE)
- created_at (TIMESTAMPTZ default NOW())
- updated_at (TIMESTAMPTZ default NOW())
- is_active (BOOLEAN default TRUE)

**users**
- id (UUID, PK)
- tenant_id (UUID, FK → tenants.id)
- email (VARCHAR, UNIQUE)
- hashed_password (VARCHAR)
- full_name (VARCHAR)
- role (ENUM: 'admin', 'analyst', 'viewer')
- is_active (BOOLEAN default TRUE)
- created_at (TIMESTAMPTZ default NOW())
- updated_at (TIMESTAMPTZ default NOW())

**alert_sources**
- id (UUID, PK)
- tenant_id (UUID, FK → tenants.id)
- name (VARCHAR)
- type (ENUM: 'webhook', 'api', 'manual')
- config (JSONB)
- is_active (BOOLEAN default TRUE)
- created_at (TIMESTAMPTZ default NOW())

**alerts**
- id (UUID, PK)
- tenant_id (UUID, FK → tenants.id)
- source_id (UUID, FK → alert_sources.id)
- incident_id (UUID, FK → incidents.id, NULLABLE)
- ocsf_data (JSONB)
- raw_data (JSONB)
- risk_score (FLOAT)
- severity (ENUM: 'low', 'medium', 'high', 'critical')
- status (ENUM: 'open', 'investigating', 'resolved', 'dismissed')
- created_at (TIMESTAMPTZ default NOW())
- updated_at (TIMESTAMPTZ default NOW())
- processed_at (TIMESTAMPTZ, NULLABLE)

**incidents**
- id (UUID, PK)
- tenant_id (UUID, FK → tenants.id)
- title (VARCHAR)
- description (TEXT)
- risk_score (FLOAT)
- severity (ENUM: 'low', 'medium', 'high', 'critical')
- status (ENUM: 'open', 'investigating', 'resolved', 'closed')
- ai_summary (TEXT, NULLABLE)
- recommended_actions (JSONB, NULLABLE)
- threat_intel_results (JSONB, NULLABLE)
- created_at (TIMESTAMPTZ default NOW())
- updated_at (TIMESTAMPTZ default NOW())
- resolved_at (TIMESTAMPTZ, NULLABLE)

**incident_alerts** (junction table)
- id (UUID, PK)
- incident_id (UUID, FK → incidents.id)
- alert_id (UUID, FK → alerts.id)
- correlation_score (FLOAT)
- correlation_reason (TEXT)
- created_at (TIMESTAMPTZ default NOW())

**investigation_notes**
- id (UUID, PK)
- incident_id (UUID, FK → incidents.id)
- user_id (UUID, FK → users.id)
- content (TEXT)
- created_at (TIMESTAMPTZ default NOW())

**feedback**
- id (UUID, PK)
- incident_id (UUID, FK → incidents.id)
- user_id (UUID, FK → users.id)
- rating (INTEGER 1-5)
- comments (TEXT, NULLABLE)
- ai_summary_useful (BOOLEAN)
- recommended_actions_useful (BOOLEAN)
- created_at (TIMESTAMPTZ default NOW())

**threat_intel_cache**
- id (UUID, PK)
- indicator (VARCHAR)
- indicator_type (ENUM: 'ip', 'domain', 'url', 'hash')
- data (JSONB)
- source (VARCHAR)
- cached_at (TIMESTAMPTZ default NOW())
- expires_at (TIMESTAMPTZ)

---

## 5. Implementation Roadmap (5 Phases)

### Phase 1: Foundation & Authentication (Week 1-2)
**Goal**: Set up project structure, authentication, and user management

#### Backend Tasks:
1. Initialize FastAPI project structure
2. Configure PostgreSQL + SQLAlchemy + Alembic
3. Configure Redis for caching and sessions
4. Implement user models (tenants, users)
5. Implement authentication (JWT, password hashing)
6. Implement RBAC (admin, analyst, viewer roles)
7. Create initial database migrations
8. Write unit tests for auth/user services
9. Set up Docker Compose for local development

#### Frontend Tasks:
1. Initialize React + TypeScript project
2. Set up routing (React Router)
3. Implement login/register pages
4. Implement protected routes
5. Create basic layout (sidebar, header)

#### Deliverables:
- Working auth system with user roles
- Dockerized dev environment

---

### Phase 2: Alert Ingestion & OCSF Normalization (Week 2-3)
**Goal**: Build alert ingestion pipeline and OCSF normalization

#### Backend Tasks:
1. Implement alert models (alert_sources, alerts)
2. Create OCSF normalization utility
3. Implement alert ingestion API (webhook and REST endpoints)
4. Add alert validation
5. Create Celery task for async alert processing
6. Store normalized alerts in PostgreSQL
7. Write unit tests for alert service and normalizer

#### Frontend Tasks:
1. Create alert sources management UI
2. Build alert queue page (list view)
3. Implement alert detail view
4. Add alert filtering/sorting

#### Deliverables:
- Working alert ingestion API
- OCSF normalization for common alert formats
- Alert queue UI

---

### Phase 3: Incident Correlation & Risk Scoring (Week 3-4)
**Goal**: Implement incident creation, correlation logic, and risk scoring

#### Backend Tasks:
1. Implement incident models (incidents, incident_alerts)
2. Build time-based correlation engine
3. Build entity-based correlation (IP, user, hostname)
4. Implement risk scoring engine (severity + basic rules)
5. Create incident lifecycle management
6. Add Celery tasks for incident correlation
7. Write unit tests for incident and risk services

#### Frontend Tasks:
1. Build incident list page
2. Create incident detail view with timeline
3. Add incident correlation visualization
4. Implement risk score display
5. Build incident status management UI

#### Deliverables:
- Automated incident correlation
- Risk scoring system
- Incident management UI

---

### Phase 4: AI & Threat Intelligence (Week 4-5)
**Goal**: Integrate AI investigation summaries and threat intel lookup

#### Backend Tasks:
1. Implement AI service with LangChain
2. Build LLM prompt templates for investigation summaries
3. Create recommended actions generation
4. Integrate threat intelligence APIs (VirusTotal, AbuseIPDB)
5. Add threat intel caching in Redis + PostgreSQL
6. Create Celery tasks for async AI processing
7. Write unit tests for AI and threat intel services

#### Frontend Tasks:
1. Display AI investigation summaries
2. Show recommended actions
3. Build threat intel lookup results UI
4. Add AI processing status indicators

#### Deliverables:
- AI-generated investigation summaries
- Threat intelligence integration
- Recommended actions

---

### Phase 5: Dashboard, Feedback & Polish (Week 5-6)
**Goal**: Build SOC dashboard, feedback system, and polish MVP

#### Backend Tasks:
1. Implement feedback model and service
2. Build dashboard analytics endpoints
3. Add WebSocket support for real-time updates
4. Implement logging and monitoring
5. Add input validation and error handling
6. Security hardening (CORS, rate limiting)
7. Write integration tests
8. Performance optimization

#### Frontend Tasks:
1. Build SOC dashboard (metrics, charts)
2. Implement feedback UI
3. Add real-time updates via WebSockets
4. Create admin panel (user/source management)
5. Polish UI/UX
6. Add responsive design

#### Deliverables:
- SOC dashboard
- Analyst feedback system
- Production-ready MVP

---

## 6. MVP Feature Checklist

### ✅ Must-Have Features
1. **Authentication**
   - User registration/login
   - JWT-based auth
   - Password reset
   
2. **User Roles**
   - Admin: full access
   - Analyst: investigate incidents, provide feedback
   - Viewer: read-only access

3. **Alert Ingestion API**
   - Webhook endpoint
   - REST API endpoint
   - Source management

4. **OCSF Normalization**
   - Support for common alert formats
   - Normalizer utility

5. **Incident Correlation**
   - Time-based correlation
   - Entity-based (IP, user, hostname)
   - Manual correlation

6. **Risk Scoring**
   - Alert-level risk score
   - Incident-level risk score
   - Severity levels

7. **AI Investigation Summary**
   - LLM-generated summaries
   - Context-aware analysis

8. **Threat Intelligence Lookup**
   - IP/domain/hash lookup
   - Cached results
   - Multiple sources

9. **SOC Dashboard**
   - Key metrics (alert count, incident count, risk distribution)
   - Charts and visualizations
   - Real-time updates

10. **Analyst Feedback**
    - Rating system
    - Comments
    - AI usefulness feedback

---

## 7. Security for MVP

### Authentication & Authorization
- JWT with refresh tokens
- Password hashing (bcrypt)
- Role-based access control (RBAC)
- Input validation with Pydantic

### Data Security
- TLS 1.3 for all traffic
- Environment variables for secrets
- Secure headers (CSP, HSTS, X-Frame-Options)
- SQL injection protection (SQLAlchemy ORM)

### Application Security
- Rate limiting (slowapi)
- CORS configuration
- Request validation
- Error handling without exposing sensitive info

---

## 8. Deployment for MVP

### Local Development
- Docker Compose with:
  - FastAPI backend
  - React frontend (dev server)
  - PostgreSQL
  - Redis
  - pgAdmin (optional)

### Production Deployment (Simple)
- Docker Compose on a single VPS
- Nginx as reverse proxy
- Let's Encrypt for SSL
- Volume mounts for data persistence
- Basic monitoring with Prometheus + Grafana (optional)

---

## 9. Next Steps After MVP

Once MVP is validated:
1. Add Elasticsearch for better search
2. Implement more sophisticated correlation rules
3. Add SOAR integrations
4. Implement multi-region deployment
5. Add advanced ML models
6. Introduce microservices architecture
7. Add compliance features (audit logs, etc.)
