# OAuth Connection Management API

## Overview

Complete backend API for managing OAuth connections, tokens, and multi-account support for SaaS automation platforms.

**Base URL:** `http://localhost:8000/api/oauth`

**Supported Connectors:** Gmail, LinkedIn, Facebook, Stripe, Shopify, YouTube, Calendar, Drive, Instagram, WhatsApp, and more

**Database:** PostgreSQL (Prisma Cloud)

---

## Setup Requirements

### 1. Create OAuth Apps for Each Connector

Before using any connector, you must create an OAuth application with the provider:

#### Google Services (Gmail, YouTube, Calendar, Drive, Business)
1. Go to [Google Cloud Console](https://console.cloud.google.com/)
2. Create a new project or select existing
3. Enable required APIs (Gmail API, YouTube API, Calendar API, etc.)
4. Go to **Credentials** → **Create Credentials** → **OAuth 2.0 Client ID**
5. Set application type to **Web application**
6. Add authorized redirect URI: `http://localhost:8000/api/oauth/callback`
7. Copy **Client ID** and **Client Secret**

#### LinkedIn
1. Go to [LinkedIn Developers](https://www.linkedin.com/developers/apps)
2. Create a new app
3. Add **Authorized redirect URLs**: `http://localhost:8000/api/oauth/callback`
4. Request access to required products (Sign In with LinkedIn, Share on LinkedIn, etc.)
5. Copy **Client ID** and **Client Secret**

#### Facebook/Instagram/WhatsApp
1. Go to [Meta for Developers](https://developers.facebook.com/)
2. Create a new app
3. Add **Facebook Login** product
4. Add **Valid OAuth Redirect URIs**: `http://localhost:8000/api/oauth/callback`
5. Copy **App ID** (Client ID) and **App Secret** (Client Secret)

#### Stripe
1. Go to [Stripe Dashboard](https://dashboard.stripe.com/)
2. Navigate to **Settings** → **Connect**
3. Add redirect URI: `http://localhost:8000/api/oauth/callback`
4. Copy **Client ID** and **Secret Key**

#### Shopify
1. Go to [Shopify Partners](https://partners.shopify.com/)
2. Create a new app
3. Set **App URL** and **Allowed redirection URL(s)**: `http://localhost:8000/api/oauth/callback`
4. Copy **API key** (Client ID) and **API secret key** (Client Secret)

### 2. App Verification for Advanced Scopes

Some scopes require app verification:

#### Google
- **Sensitive scopes** (Gmail send, Drive full access, Calendar write) require OAuth verification
- Submit app for verification at [Google OAuth Verification](https://support.google.com/cloud/answer/9110914)
- Process takes 4-6 weeks
- Until verified, limited to 100 test users

#### LinkedIn
- **Marketing Developer Platform** access required for:
  - `w_organization_social` (Post as organization)
  - `r_organization_social` (Read organization posts)
- Apply at [LinkedIn Partner Programs](https://www.linkedin.com/help/linkedin/answer/a545808)
- Requires business verification

#### Facebook/Instagram
- **Business verification** required for:
  - `pages_manage_posts`
  - `instagram_content_publish`
  - `whatsapp_business_messaging`
- Submit at [Meta Business Verification](https://developers.facebook.com/docs/development/release/business-verification)

### 3. Configure Redirect URIs

Add the callback URL to each OAuth app's allowed redirect URIs:

**Development:**
```
http://localhost:8000/api/oauth/callback
```

**Production:**
```
https://yourdomain.com/api/oauth/callback
```

### 4. Environment Variables Setup

Add OAuth credentials to your `.env` file:

```env
# Application
APP_URL=http://localhost:8000

# Google Services (Gmail, YouTube, Calendar, Drive, Business)
GOOGLE_CLIENT_ID=your_google_client_id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-your_google_client_secret

# LinkedIn
LINKEDIN_CLIENT_ID=your_linkedin_client_id
LINKEDIN_CLIENT_SECRET=your_linkedin_client_secret

# Facebook/Instagram/WhatsApp
FACEBOOK_CLIENT_ID=your_facebook_app_id
FACEBOOK_CLIENT_SECRET=your_facebook_app_secret

# Stripe
STRIPE_CLIENT_ID=ca_your_stripe_client_id
STRIPE_CLIENT_SECRET=sk_your_stripe_secret_key

# Shopify
SHOPIFY_CLIENT_ID=your_shopify_api_key
SHOPIFY_CLIENT_SECRET=your_shopify_api_secret

# Database
DB_CONNECTION=pgsql
DB_HOST=db.prisma.io
DB_PORT=5432
DB_DATABASE=postgres
DB_USERNAME=your_username
DB_PASSWORD=your_password
```

---

## Database Schema

```sql
CREATE TABLE oauth_connections (
  id BIGSERIAL PRIMARY KEY,
  user_id BIGINT NOT NULL,
  connector_id VARCHAR(255) NOT NULL,
  account_identifier VARCHAR(255),
  access_token TEXT NOT NULL,
  refresh_token TEXT,
  token_type VARCHAR(255) DEFAULT 'Bearer',
  expires_at TIMESTAMP,
  scopes JSON NOT NULL,
  status VARCHAR(255) CHECK (status IN ('active', 'expired', 'revoked')) DEFAULT 'active',
  connector_metadata JSON,
  granted_at TIMESTAMP NOT NULL,
  created_at TIMESTAMP,
  updated_at TIMESTAMP,
  UNIQUE (user_id, connector_id, account_identifier)
);

CREATE INDEX idx_user_connector ON oauth_connections(user_id, connector_id);
CREATE INDEX idx_status ON oauth_connections(status);
CREATE INDEX idx_expires_at ON oauth_connections(expires_at);
```

**Key Features:**
- `account_identifier`: Unique identifier per account (email for Gmail, user ID for LinkedIn/Facebook)
- `connector_metadata`: Stores user profile data (email, name, picture, etc.)
- `scopes`: JSON array of granted OAuth scopes
- `status`: Connection status (active, expired, revoked)
- Supports multiple accounts per connector per user

---

## 1. Authentication & Authorization

### 1.1 Initiate OAuth Flow

**Endpoint:** `GET /api/oauth/authorize`

**Purpose:** Redirects user to OAuth provider's authorization page

**Query Parameters:**
- `userId` (required): User identifier
- `connectorId` (required): Connector identifier (`gmail`, `linkedin`, `facebook`, `stripe`, `shopify`)
- `scopes` (required): Space-separated list of requested scopes
- `redirectUri` (optional): Custom redirect URI

**Behavior:** Redirects to OAuth provider (not JSON response)

**Example:**
```
GET /api/oauth/authorize?userId=user123&connectorId=gmail&scopes=openid%20email%20profile
```

**Error Response:**
```html
<h1>Error</h1><p>Unsupported connector: invalid_connector</p>
```

---

### 1.2 OAuth Callback Handler

**Endpoint:** `GET /api/oauth/callback`

**Purpose:** Handles OAuth provider callback, exchanges code for tokens, stores in database

**Query Parameters:**
- `code` (required): Authorization code from provider
- `state` (required): State token (contains userId, connectorId, CSRF token)

**Process:**
1. Validates state token
2. Exchanges code for access/refresh tokens
3. Fetches user profile metadata from OAuth provider
4. Extracts `account_identifier` from metadata (email or user ID)
5. Stores/updates in `oauth_connections` table
6. Returns HTML page that sends postMessage to parent window

**Success Response (HTML):**
```html
<script>
  window.opener.postMessage({ 
    success: true, 
    connectorId: "gmail" 
  }, "*");
  window.close();
</script>
<p>Authorization complete. You can close this window.</p>
```

**Error Response (HTML):**
```html
<script>
  window.opener.postMessage({ 
    success: false, 
    error: "Failed to exchange code for tokens" 
  }, "*");
  window.close();
</script>
<p>Authorization failed: [error message]</p>
```

---

## 2. Connection Management

### 2.1 Check Connection Status

**Endpoint:** `GET /api/oauth/connections/:userId/:connectorId`

**Purpose:** Returns all accounts connected for a specific connector

**Path Parameters:**
- `userId`: User identifier
- `connectorId`: Connector identifier

**Example:**
```
GET /api/oauth/connections/user123/gmail
```

**Response (Connected):**
```json
{
  "connected": true,
  "connectorId": "gmail",
  "accounts": [
    {
      "accountIdentifier": "user@gmail.com",
      "status": "active",
      "grantedScopes": ["openid", "email", "profile"],
      "grantedAt": "2025-01-15T12:00:00.000000Z",
      "expiresAt": "2025-01-15T13:00:00.000000Z",
      "metadata": {
        "email": "user@gmail.com",
        "id": "123456789",
        "name": "John Doe",
        "picture": "https://..."
      }
    },
    {
      "accountIdentifier": "work@gmail.com",
      "status": "active",
      "grantedScopes": ["openid", "email", "profile"],
      "grantedAt": "2025-01-15T14:00:00.000000Z",
      "expiresAt": "2025-01-15T15:00:00.000000Z",
      "metadata": {
        "email": "work@gmail.com",
        "id": "987654321",
        "name": "John Work"
      }
    }
  ]
}
```

**Response (Not Connected):**
```json
{
  "connected": false,
  "connectorId": "gmail"
}
```

---

### 2.2 List All User Connections

**Endpoint:** `GET /api/oauth/connections/:userId`

**Purpose:** Returns all OAuth connections for a user across all connectors

**Path Parameters:**
- `userId`: User identifier

**Query Parameters:**
- `status` (optional): Filter by status (`active`, `expired`, `revoked`)
- `includeMetadata` (optional): Include connector metadata (default: `false`)

**Example:**
```
GET /api/oauth/connections/user123?status=active&includeMetadata=true
```

**Response:**
```json
{
  "userId": "user123",
  "connections": [
    {
      "connectorId": "gmail",
      "accountIdentifier": "user@gmail.com",
      "status": "active",
      "grantedScopes": ["openid", "email", "profile"],
      "grantedAt": "2025-01-15T12:00:00.000000Z",
      "expiresAt": "2025-01-15T13:00:00.000000Z",
      "metadata": {
        "email": "user@gmail.com",
        "id": "123456789"
      }
    },
    {
      "connectorId": "linkedin",
      "accountIdentifier": "linkedin-user-id",
      "status": "active",
      "grantedScopes": ["openid", "profile", "email"],
      "grantedAt": "2025-01-15T14:00:00.000000Z",
      "expiresAt": "2025-01-15T15:00:00.000000Z"
    }
  ],
  "total": 2
}
```

---

### 2.3 Revoke Connection

**Endpoint:** `DELETE /api/oauth/connections/:userId/:connectorId/:accountIdentifier`

**Purpose:** Revokes a specific account connection

**Path Parameters:**
- `userId`: User identifier
- `connectorId`: Connector identifier
- `accountIdentifier`: Account identifier (email or ID from metadata)

**Query Parameters:**
- `revokeFromProvider` (optional): Revoke token from OAuth provider (default: `true`)

**Example:**
```
DELETE /api/oauth/connections/user123/gmail/user@gmail.com?revokeFromProvider=true
```

**Response:**
```json
{
  "success": true,
  "connectorId": "gmail",
  "accountIdentifier": "user@gmail.com",
  "revokedAt": "2025-01-15T10:00:00.000000Z"
}
```

**Error Response:**
```json
{
  "error": "Connection not found"
}
```

---

### 2.4 Update Scopes (Request Re-authorization)

**Endpoint:** `PATCH /api/oauth/connections/:userId/:connectorId/:accountIdentifier/scopes`

**Purpose:** Requests additional scopes for an existing connection

**Path Parameters:**
- `userId`: User identifier
- `connectorId`: Connector identifier
- `accountIdentifier`: Account identifier

**Request Body:**
```json
{
  "additionalScopes": [
    "https://www.googleapis.com/auth/calendar",
    "https://www.googleapis.com/auth/drive.file"
  ]
}
```

**Example:**
```
PATCH /api/oauth/connections/user123/gmail/user@gmail.com/scopes
Content-Type: application/json

{
  "additionalScopes": ["https://www.googleapis.com/auth/calendar"]
}
```

**Response:**
```json
{
  "requiresReauth": true,
  "authUrl": "https://accounts.google.com/o/oauth2/v2/auth?client_id=...&scope=openid+email+profile+https://www.googleapis.com/auth/calendar&...",
  "message": "Additional scopes require re-authorization"
}
```

**Error Response:**
```json
{
  "error": "Connection not found"
}
```

---

## 3. Token Management

### 3.1 Get Valid Access Token

**Endpoint:** `GET /api/oauth/token/:userId/:connectorId/:accountIdentifier`

**Purpose:** Returns a valid access token, automatically refreshing if expired or expiring within 5 minutes

**Path Parameters:**
- `userId`: User identifier
- `connectorId`: Connector identifier
- `accountIdentifier`: Account identifier

**Example:**
```
GET /api/oauth/token/user123/gmail/user@gmail.com
```

**Process:**
1. Retrieves connection from database
2. Checks if token expires in next 5 minutes
3. Auto-refreshes if needed using refresh token
4. Updates database with new tokens
5. Returns valid access token

**Response:**
```json
{
  "accessToken": "ya29.a0AfH6SMBx...",
  "tokenType": "Bearer",
  "expiresAt": "2025-01-15T13:00:00.000000Z",
  "scopes": ["openid", "email", "profile"]
}
```

**Error Cases:**

**404 - Connection Not Found:**
```json
{
  "error": "Connection not found"
}
```

**401 - Connection Not Active:**
```json
{
  "error": "Connection is not active"
}
```

**401 - Token Expired, No Refresh Token:**
```json
{
  "error": "Token expired and no refresh token available"
}
```

**500 - Refresh Failed:**
```json
{
  "error": "Failed to refresh token"
}
```

---

### 3.2 Force Refresh Token

**Endpoint:** `POST /api/oauth/token/:userId/:connectorId/:accountIdentifier/refresh`

**Purpose:** Manually triggers token refresh

**Path Parameters:**
- `userId`: User identifier
- `connectorId`: Connector identifier
- `accountIdentifier`: Account identifier

**Example:**
```
POST /api/oauth/token/user123/gmail/user@gmail.com/refresh
```

**Process:**
1. Retrieves refresh token from database
2. Calls provider's token refresh endpoint
3. Updates `oauth_connections` table with new tokens
4. Marks connection as `active`
5. Returns new access token

**Response:**
```json
{
  "success": true,
  "accessToken": "ya29.a0AfH6SMBx...",
  "expiresAt": "2025-01-15T13:00:00.000000Z",
  "refreshedAt": "2025-01-15T12:00:00.000000Z"
}
```

**Error Cases:**

**404 - Connection Not Found:**
```json
{
  "error": "Connection not found"
}
```

**400 - No Refresh Token:**
```json
{
  "error": "No refresh token available"
}
```

**500 - Refresh Failed:**
```json
{
  "error": "Failed to refresh token: [error details]"
}
```

---

## 4. Supported Connectors

### Gmail
- **Connector ID:** `gmail`
- **Scopes:** `openid email profile https://www.googleapis.com/auth/gmail.send`
- **Account Identifier:** Email address
- **Metadata Fields:** `{ id, email, verified_email, name, given_name, family_name, picture, hd }`

### LinkedIn
- **Connector ID:** `linkedin`
- **Scopes:** `openid profile email`
- **Account Identifier:** LinkedIn user ID (sub)
- **Metadata Fields:** `{ sub, name, email }`

### Facebook
- **Connector ID:** `facebook`
- **Scopes:** `email public_profile`
- **Account Identifier:** Facebook user ID
- **Metadata Fields:** `{ id, name, email }`

### Stripe
- **Connector ID:** `stripe`
- **Scopes:** Stripe-specific
- **Account Identifier:** `stripe_user_id`

### Shopify
- **Connector ID:** `shopify`
- **Scopes:** Shopify-specific
- **Account Identifier:** Shop domain

---

## 5. Frontend Integration

### OAuth Popup Flow

```javascript
const connectService = (userId, connectorId, scopes) => {
  // Open popup window
  const popup = window.open(
    `http://localhost:8000/api/oauth/authorize?userId=${userId}&connectorId=${connectorId}&scopes=${encodeURIComponent(scopes)}`,
    'oauth',
    'width=600,height=700'
  );

  // Listen for postMessage from callback
  const handleMessage = (event) => {
    if (event.data.success) {
      console.log('✓ Connected:', event.data.connectorId);
      // Refresh UI, fetch connections, etc.
      window.removeEventListener('message', handleMessage);
    } else if (event.data.error) {
      console.error('✗ Failed:', event.data.error);
      window.removeEventListener('message', handleMessage);
    }
  };

  window.addEventListener('message', handleMessage);
};

// Usage Examples
connectService('user123', 'gmail', 'openid email profile');
connectService('user123', 'linkedin', 'openid profile email');
```

### Fetch User Connections

```javascript
const fetchConnections = async (userId) => {
  const response = await fetch(`http://localhost:8000/api/oauth/connections/${userId}?includeMetadata=true`);
  const data = await response.json();
  
  console.log(`Total connections: ${data.total}`);
  data.connections.forEach(conn => {
    console.log(`${conn.connectorId}: ${conn.accountIdentifier} (${conn.status})`);
  });
};
```

### Get Valid Token for API Calls

```javascript
const getToken = async (userId, connectorId, accountIdentifier) => {
  const response = await fetch(
    `http://localhost:8000/api/oauth/token/${userId}/${connectorId}/${encodeURIComponent(accountIdentifier)}`
  );
  
  if (response.ok) {
    const data = await response.json();
    return data.accessToken; // Use this token for API calls
  } else {
    const error = await response.json();
    console.error('Token error:', error.error);
    return null;
  }
};

// Usage
const token = await getToken('user123', 'gmail', 'user@gmail.com');
// Use token to call Gmail API
```

---

## 6. Environment Variables

```env
# Application
APP_URL=http://localhost:8000

# OAuth Connectors
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret

LINKEDIN_CLIENT_ID=your_linkedin_client_id
LINKEDIN_CLIENT_SECRET=your_linkedin_client_secret

FACEBOOK_CLIENT_ID=your_facebook_client_id
FACEBOOK_CLIENT_SECRET=your_facebook_client_secret

STRIPE_CLIENT_ID=your_stripe_client_id
STRIPE_CLIENT_SECRET=your_stripe_client_secret

SHOPIFY_CLIENT_ID=your_shopify_client_id
SHOPIFY_CLIENT_SECRET=your_shopify_client_secret

# Database
DB_CONNECTION=pgsql
DB_HOST=db.prisma.io
DB_PORT=5432
DB_DATABASE=postgres
DB_USERNAME=your_username
DB_PASSWORD=your_password
```

---

## 7. API Endpoint Summary

| Method | Endpoint | Purpose |
|--------|----------|---------|
| GET | `/api/oauth/authorize` | Initiate OAuth flow |
| GET | `/api/oauth/callback` | Handle OAuth callback |
| GET | `/api/oauth/connections/:userId/:connectorId` | Check connector status |
| GET | `/api/oauth/connections/:userId` | List all connections |
| DELETE | `/api/oauth/connections/:userId/:connectorId/:accountIdentifier` | Revoke connection |
| PATCH | `/api/oauth/connections/:userId/:connectorId/:accountIdentifier/scopes` | Update scopes |
| GET | `/api/oauth/token/:userId/:connectorId/:accountIdentifier` | Get valid token |
| POST | `/api/oauth/token/:userId/:connectorId/:accountIdentifier/refresh` | Force refresh token |

---

## 8. Notes for Frontend Developers

1. **Multiple Accounts:** Users can connect multiple accounts per connector (e.g., 2 Gmail accounts). Always use `accountIdentifier` to specify which account.

2. **Token Management:** Use the `/token` endpoint to get valid tokens. It automatically refreshes expired tokens.

3. **PostMessage Events:** The OAuth callback sends postMessage to the parent window. Listen for `{ success: true/false, connectorId, error }`.

4. **Account Identifiers:**
   - Gmail: Email address
   - LinkedIn: User ID (sub field)
   - Facebook: User ID

5. **Status Values:** `active`, `expired`, `revoked`

6. **Timestamps:** All timestamps are in ISO 8601 format with timezone (e.g., `2025-01-15T12:00:00.000000Z`)
