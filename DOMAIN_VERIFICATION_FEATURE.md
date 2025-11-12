# Domain Addition & Verification Feature

## Overview

This feature adds automated domain addition and verification functionality to the GBot application. It integrates with Google Workspace (for domain management) and Namecheap (for DNS TXT record management) to streamline the domain verification process.

## Features

- **Bulk Domain Processing**: Add and verify multiple domains at once
- **Apex Detection**: Automatically converts subdomains to their registrable apex domains
- **Google Workspace Integration**: Adds domains to Workspace and retrieves verification tokens
- **Namecheap DNS Integration**: Creates TXT records in Namecheap without deleting existing records
- **Real-time Status Tracking**: Live progress updates per domain
- **Dry-run Mode**: Test the process without making DNS changes
- **Skip Verified**: Automatically skip domains that are already verified

## Installation & Setup

### 1. Install Dependencies

```bash
pip install -r requirements.txt
```

New dependency added: `publicsuffix2==2.2.0`

### 2. Run Database Migration

```bash
python migrations/add_domain_verification_tables.py
```

This creates two new tables:
- `namecheap_config`: Stores Namecheap API credentials
- `domain_operation`: Tracks domain verification operations

### 3. Configure Namecheap API Credentials

The Namecheap credentials can be configured via API:

```bash
POST /api/namecheap-config
{
    "api_user": "your_api_user",
    "api_key": "your_api_key",
    "username": "your_namecheap_username",
    "client_ip": "your_client_ip"
}
```

Or you can add them directly to the database in the `namecheap_config` table.

**Note**: The client IP must be whitelisted in your Namecheap account settings.

### 4. Update Google OAuth Scopes

The application now requires the Site Verification scope. If you need to re-authenticate:

1. Go to Settings
2. Re-authenticate your Google account
3. The new scope (`https://www.googleapis.com/auth/siteverification`) will be requested automatically

## Usage

### Via Web UI

1. Navigate to **Tab 3: Bulk Domain Change & SMTP/CSV**
2. Scroll to the **"Domain Addition & Verification"** section
3. Paste domains (one per line) in the textarea
4. Configure options:
   - **Dry-run**: Check to test without making DNS changes
   - **Skip if domain already verified**: Check to skip verified domains (default: on)
5. Click **"Start Process"**
6. Monitor progress in the status table and log panel

### Via API

#### Start Domain Verification

```bash
POST /api/domains/add-and-verify
Content-Type: application/json

{
    "domains": ["example.com", "sub.team.example.co.uk"],
    "dryRun": false,
    "skipVerified": true
}
```

Response:
```json
{
    "success": true,
    "job_id": "6a0b6a7c-3b53-4de1-9a4d-1b0b4d8c5142",
    "accepted": 2
}
```

#### Get Status

```bash
GET /api/domains/status?job_id=<uuid>
```

Response:
```json
{
    "success": true,
    "results": [
        {
            "domain": "example.com",
            "apex": "example.com",
            "workspace": "success",
            "dns": "success",
            "verify": "success",
            "message": "Domain verified successfully",
            "updated_at": "2024-01-15T10:30:00Z"
        }
    ],
    "total": 1
}
```

## How It Works

### Process Flow

1. **Input Normalization**: Domains are trimmed, lowercased, and deduplicated
2. **Apex Detection**: Subdomains are converted to their registrable apex using Public Suffix List
3. **Skip Check**: If enabled, checks if domain is already verified and skips if so
4. **Workspace Addition**: Adds domain to Google Workspace (if not already present)
5. **Token Retrieval**: Gets DNS TXT verification token from Google Site Verification API
6. **DNS Update**: Creates/updates TXT record in Namecheap (preserving all existing records)
7. **Verification**: Polls Google to verify domain (with retries and backoff)

### Apex Detection

The system uses the Public Suffix List to correctly identify registrable domains:

- `mail.team.example.co.uk` → `example.co.uk`
- `sub.example.com` → `example.com`
- `example.com` → `example.com`

### DNS Record Management

The Namecheap integration:
- Fetches all existing DNS records
- Adds the new TXT record to the list
- Updates all records atomically (preserving MX, A, CNAME, etc.)
- Supports multiple TXT records at the same host

### Verification Retry Logic

- Maximum 10 attempts
- 20-second initial wait for DNS propagation
- 30-second intervals between retries
- Total timeout: ~6-8 minutes

## Status Values

### Workspace Status
- `pending`: Not yet processed
- `success`: Domain added successfully
- `failed`: Failed to add domain
- `skipped`: Domain already exists or was skipped

### DNS Status
- `pending`: Not yet processed
- `success`: TXT record created/updated
- `failed`: Failed to create TXT record
- `dry-run`: Dry-run mode (no changes made)
- `skipped`: Skipped (domain already verified)

### Verification Status
- `pending`: Verification in progress
- `success`: Domain verified
- `failed`: Verification failed after retries
- `skipped`: Skipped (dry-run or already verified)

## Error Handling

The system distinguishes between:
- **Fatal errors**: Domain not found, invalid credentials, etc.
- **Retryable errors**: Rate limits (429), server errors (5xx)

Retryable errors use exponential backoff.

## Database Schema

### DomainOperation Table

```sql
CREATE TABLE domain_operation (
    id VARCHAR(36) PRIMARY KEY,
    job_id VARCHAR(36) NOT NULL,
    input_domain VARCHAR(255) NOT NULL,
    apex_domain VARCHAR(255) NOT NULL,
    workspace_status VARCHAR(50) DEFAULT 'pending',
    dns_status VARCHAR(50) DEFAULT 'pending',
    verify_status VARCHAR(50) DEFAULT 'pending',
    message TEXT,
    raw_log JSONB,  -- JSON in SQLite
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

### NamecheapConfig Table

```sql
CREATE TABLE namecheap_config (
    id SERIAL PRIMARY KEY,
    api_user VARCHAR(255) NOT NULL,
    api_key VARCHAR(255) NOT NULL,
    username VARCHAR(255) NOT NULL,
    client_ip VARCHAR(45) NOT NULL,
    is_configured BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
```

## Troubleshooting

### "Namecheap configuration not found"
- Configure Namecheap credentials via `/api/namecheap-config` endpoint
- Ensure `is_configured` is set to `true` in the database

### "Site Verification API error"
- Ensure the Site Verification scope is included in your OAuth token
- Re-authenticate if necessary

### "Zone not found in Namecheap account"
- Verify the domain is registered in your Namecheap account
- Check that the apex domain matches the zone name in Namecheap

### "Verification failed after retries"
- DNS propagation may take longer than expected
- Check the TXT record manually in Namecheap
- Verify the record value matches exactly what Google expects

## Files Added/Modified

### New Files
- `services/zone_utils.py`: Apex detection utilities
- `services/google_domains_service.py`: Google Workspace domain management
- `services/namecheap_dns_service.py`: Namecheap DNS management
- `routes/dns_manager.py`: Flask routes for domain verification
- `migrations/add_domain_verification_tables.py`: Database migration

### Modified Files
- `database.py`: Added `NamecheapConfig` and `DomainOperation` models
- `app.py`: Registered DNS manager blueprint, added imports
- `config.py`: Added Site Verification scope
- `requirements.txt`: Added `publicsuffix2`
- `templates/dashboard.html`: Added UI component in tab 3

## Security Notes

- Namecheap API credentials are stored in the database (consider encryption for production)
- Google OAuth tokens are already secured via existing mechanisms
- All API calls use HTTPS
- Client IP must be whitelisted in Namecheap account

## Future Enhancements

- Support for other DNS providers (Cloudflare, Route53, etc.)
- Bulk domain import from CSV
- Email notifications on completion
- Detailed error reporting with actionable messages
- Domain verification history and audit logs
