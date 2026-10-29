# Shared Multi-App Flask Authentication Backend (Supabase PostgreSQL + Google Sign-In)

A centralized, production-ready authentication backend designed to serve multiple React Native Expo apps, web frontends, and client services from a single Supabase PostgreSQL database.

---

## 🏗️ Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │          Google OAuth Servers          │
                      │   (Public Keys & Certs Verification)   │
                      └───────────────────▲────────────────────┘
                                          │ Server-side ID Token Verification
                                          │ (aud, iss, exp, signature, sub)
┌────────────────────────┐    Google ID   │
│   HealthScanApp (Expo) │    Token JWT   │
├────────────────────────┤───────────────►├────────────────────────────────────────┐
│ Future App 1 (Expo/Web)│                │            Flask Backend API           │
├────────────────────────┤◄───────────────┤   - Centralized Token & Session Engine │
│ Future App 2 (Portal)  │  Access Token  │   - Multi-App Registry & RBAC          │
└────────────────────────┘  + Refresh Tok │   - Reusable Middleware (@require_auth)│
                                          └───────────────────┬────────────────────┘
                                                              │ Direct Pooled Connection
                                                              │ (psycopg2 / SSL)
                                          ┌───────────────────▼────────────────────┐
                                          │       Supabase PostgreSQL DB          │
                                          │  - public.users (Global accounts)      │
                                          │  - public.apps (Application registry)  │
                                          │  - public.user_app_access (Per-app RBAC│
                                          │  - public.refresh_tokens (Hashed token)│
                                          └────────────────────────────────────────┘
```

---

## 🔒 Security Highlights

1. **Server-Side Google ID Token Verification**: Validates cryptographic signature, expiry (`exp`), issuer (`accounts.google.com`), and target audience (`GOOGLE_CLIENT_IDS`). Unverified emails are rejected.
2. **Idempotent User Matching**: Matches by verified `google_sub`. If an account previously existed by email, it links the Google subject ID without creating duplicate accounts.
3. **Multi-App Registry & RBAC**: Every request specifies an `app_key` (via `X-App-Key` header or payload). Permissions and roles (`user`, `admin`, `support`) are enforced independently per app in `public.user_app_access`.
4. **Hashed Refresh Tokens**: High-entropy raw refresh tokens (`secrets.token_urlsafe(48)`) are returned to the client once. **Only the SHA-256 hash is stored in the database.**
5. **Refresh Token Rotation & Anti-Replay**: Every refresh operation revokes the previous token and issues a brand new pair. Replay attempts with an already-revoked token are immediately rejected.
6. **Stateless JWT Access Tokens**: Short-lived (default 15 minutes) signed with `HS256` or `RS256`.

---

## 🗄️ Database Changes & SQL Queries for Supabase

You provided the base schema. To ensure full compatibility with this app and future apps, run this short query in your **Supabase Dashboard -> SQL Editor**:

```sql
-- ==============================================================================
-- 1. SEED YOUR HEALTHSCAN APP INTO public.apps
-- ==============================================================================
INSERT INTO public.apps (app_key, display_name)
VALUES 
    ('main_app', 'Main App'),
    ('healthscan_app', 'HealthScan App')
ON CONFLICT (app_key) DO UPDATE
SET display_name = EXCLUDED.display_name;

-- ==============================================================================
-- 2. SUPABASE ROW LEVEL SECURITY (RLS) POLICIES
-- ==============================================================================
-- Note: When your Flask backend connects using the standard connection string
-- (as user 'postgres' or using the service_role key), PostgreSQL automatically
-- BYPASSES RLS.
--
-- However, if you ever connect via custom roles or want full defense-in-depth,
-- ensure the service role can access all tables:

CREATE POLICY "Service role full access on users"
ON public.users
FOR ALL
TO service_role
USING (true)
WITH CHECK (true);

CREATE POLICY "Service role full access on apps"
ON public.apps
FOR ALL
TO service_role
USING (true)
WITH CHECK (true);

CREATE POLICY "Service role full access on user_app_access"
ON public.user_app_access
FOR ALL
TO service_role
USING (true)
WITH CHECK (true);

CREATE POLICY "Service role full access on refresh_tokens"
ON public.refresh_tokens
FOR ALL
TO service_role
USING (true)
WITH CHECK (true);
```

---

## 🚀 Setup & Installation Steps

### 1. Prerequisites
- Python 3.10+ (or Docker)
- A Supabase Project with the SQL schema executed
- Google Cloud Console OAuth 2.0 Client ID (Web / Android / iOS)

### 2. Configure Environment
In `backend/`, copy `.env.example` to `.env`:
```bash
cp .env.example .env
```

Edit `.env` with your actual Supabase Database credentials and Google Client IDs:
```ini
FLASK_ENV=development
FLASK_DEBUG=True
PORT=5000

# Secret key for JWT signing
JWT_SECRET_KEY=generate-a-strong-random-key-here
JWT_ACCESS_TOKEN_EXPIRES_MINUTES=15
REFRESH_TOKEN_EXPIRES_DAYS=30

# Your Google OAuth Client IDs (Web, Android, iOS - comma-separated)
GOOGLE_CLIENT_IDS=your-web-client-id.apps.googleusercontent.com

# Supabase direct/pooled connection URI from Dashboard -> Settings -> Database:
DATABASE_URL=postgresql://postgres:YOUR_PASSWORD@db.YOUR_PROJECT_REF.supabase.co:5432/postgres

# Application key for HealthScan
DEFAULT_APP_KEY=main_app
AUTO_PROVISION_USER_APP_ACCESS=True
```

### 3. Install Dependencies & Run
```bash
# Create and activate virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: .\venv\Scripts\activate

# Install requirements
pip install -r requirements.txt

# Run the development server
python run.py
```

### 4. Running via Docker (Alternative)
```bash
docker build -t healthscan-backend .
docker run -p 5000:5000 --env-file .env healthscan-backend
```

---

## 🧪 Running the Automated Test Suite

The test suite includes complete unit and integration tests using an in-memory mock database that mirrors the Supabase PostgreSQL tables, meaning **tests can run offline without live credentials**:

```bash
pytest tests/ -v
```

Tests verify:
- ✅ Cryptographic Google ID token verification (valid, expired, bad audience, unverified email)
- ✅ JWT access token creation, verification, tampering detection, and expiry
- ✅ Refresh token high-entropy generation and SHA-256 hashing
- ✅ Idempotent user creation and profile linking by lowercase email
- ✅ Deactivated user blocking (`is_active = False`)
- ✅ App resolution from `public.apps` (including inactive app blocking)
- ✅ User per-app access checks and auto-provisioning
- ✅ Refresh token rotation and replay attack prevention
- ✅ Protected endpoints with `@require_auth`
- ✅ Role-based access control with `@require_role('admin')`

---

## 📡 API Contracts

### 1. Google Sign-In / Sign-Up
- **Method & Path**: `POST /api/v1/auth/google`
- **Headers**: `Content-Type: application/json`, `X-App-Key: main_app` (optional)
- **Request Body**:
```json
{
  "id_token": "eyJhbGciOiJSUzI1NiIs...",
  "app_key": "main_app",
  "device_label": "Pixel 8 (Android 14)"
}
```
- **Response `200 OK`**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsIn...",
  "refresh_token": "k8X9...64-char-raw-token...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": {
    "id": "e4b2d56a-1234-4567-89ab-cdef01234567",
    "email": "user@example.com",
    "full_name": "Alex Johnson",
    "avatar_url": "https://lh3.googleusercontent.com/..."
  },
  "app": {
    "id": "a1b2c3d4-e5f6-7890-abcd-ef1234567890",
    "app_key": "main_app",
    "display_name": "Main App",
    "role": "user"
  }
}
```

---

### 2. Session Refresh (Token Rotation)
- **Method & Path**: `POST /api/v1/auth/refresh`
- **Request Body**:
```json
{
  "refresh_token": "k8X9...current-raw-token..."
}
```
- **Response `200 OK`**:
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiIsIn...new-access-token...",
  "refresh_token": "m3Y1...brand-new-rotated-raw-refresh-token...",
  "token_type": "Bearer",
  "expires_in": 900,
  "user": { ... },
  "app": { ... }
}
```

---

### 3. Logout (Revoke Session)
- **Method & Path**: `POST /api/v1/auth/logout`
- **Request Body**:
```json
{
  "refresh_token": "k8X9...raw-token..."
}
```
- **Response `200 OK`**:
```json
{
  "success": true,
  "message": "Session revoked successfully."
}
```

---

### 4. Current User & App Profile
- **Method & Path**: `GET /api/v1/auth/me`
- **Headers**: `Authorization: Bearer <access_token>`
- **Response `200 OK`**:
```json
{
  "user": {
    "id": "e4b2d56a-...",
    "email": "user@example.com",
    "email_verified": true,
    "full_name": "Alex Johnson",
    "avatar_url": "https://...",
    "is_active": true,
    "created_at": "2026-10-16T10:00:00Z"
  },
  "app": {
    "id": "a1b2c3d4-...",
    "app_key": "main_app",
    "display_name": "Main App",
    "role": "user",
    "is_active": true
  }
}
```

---

## 📱 How Future Apps Reuse this Backend Without Duplicating Code

When you build your 2nd, 3rd, or 4th app (e.g. `FitnessTrackerApp`, `DietPlannerApp`, `ClinicAdminPortal`):

1. **Step 1: Register the new app in `public.apps`**
   Run this single SQL command:
   ```sql
   INSERT INTO public.apps (app_key, display_name)
   VALUES ('fitness_tracker', 'Fitness Tracker App')
   ON CONFLICT (app_key) DO NOTHING;
   ```

2. **Step 2: In the new app's frontend:**
   - Copy `src/services/authApi.js` into the new app.
   - Point `EXPO_PUBLIC_API_URL` to this same Flask backend URL.
   - Set `EXPO_PUBLIC_APP_KEY=fitness_tracker`.

3. **Step 3: What happens automatically:**
   - When users log in with Google in `fitness_tracker`, the backend checks if their global user record exists in `public.users`.
   - If they already have an account from `HealthScanApp`, **the exact same global user record is reused**!
   - A new row is automatically created in `public.user_app_access` linking `(user_id, fitness_tracker_app_id)` with `role = 'user'`.
   - If you ever deactivate a user in `public.users`, they are blocked across **all** your apps instantly.
   - If you want to deactivate a user on just `fitness_tracker` while letting them keep using `HealthScanApp`, simply update `public.user_app_access.is_active = FALSE` for that specific app!
