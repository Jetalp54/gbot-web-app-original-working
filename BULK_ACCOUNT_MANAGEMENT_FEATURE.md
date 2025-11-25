# 🚀 Bulk Account Management Feature

## Overview

A new feature has been added to automate the bulk creation and deletion of users across multiple accounts. This feature is located in the **User Create/Delete/Domain** tab (Tab 2) at the top of the page.

## Features

### 1. **Bulk Account Management Section**
   - Located at the top of Tab 2 (User Create/Delete/Domain)
   - Prominent card with blue border for visibility
   - "Manage Bulk Accounts" button opens the configuration popup

### 2. **Configuration Popup**
   - **Accounts Input**: Textarea for entering multiple account emails (one per line)
   - **Users per Account**: Number input (1-1000)
   - **Domain**: Text input for the domain name
   - **Password**: Text input for the password (used for all created users)

### 3. **Parallel Processing**
   - All accounts are authenticated **in parallel** using saved Authenticators
   - User creation happens **in parallel** across all accounts
   - Maximum 10 accounts processed simultaneously

### 4. **Results Display**
   - **Copyable Format**: All created users displayed as `user:password` (one per line)
   - **Summary Statistics**: 
     - Total accounts processed
     - Total users created
     - Total failures
   - **Copy Button**: One-click copy of all user:password pairs

## How It Works

### Process Flow

1. **User Input**:
   - Enter account emails (one per line)
   - Specify number of users per account
   - Enter domain name
   - Enter password for all users

2. **Authentication** (Parallel):
   - System authenticates all accounts using saved Authenticators
   - Uses `authenticate_without_session()` function
   - Accounts without saved Authenticators will fail with clear error message

3. **User Creation** (Parallel):
   - For each authenticated account:
     - Creates specified number of users
     - Generates random first/last names
     - Creates emails: `{firstname}{lastname}{random}@{domain}`
     - Uses provided password for all users

4. **Results Display**:
   - Shows all created users in `user:password` format
   - Displays summary statistics
   - Provides copy button for easy extraction

## API Endpoint

### `/api/bulk-create-account-users`

**Method**: `POST`

**Request Body**:
```json
{
  "accounts": ["account1@domain.com", "account2@domain.com"],
  "users_per_account": 10,
  "domain": "example.com",
  "password": "SecurePass123"
}
```

**Response**:
```json
{
  "success": true,
  "total_accounts": 2,
  "total_users_created": 20,
  "total_users_failed": 0,
  "results": [
    {
      "account": "account1@domain.com",
      "authenticated": true,
      "users": [
        {
          "email": "james.smith1234@example.com",
          "password": "SecurePass123",
          "first_name": "James",
          "last_name": "Smith",
          "success": true
        }
      ],
      "error": null
    }
  ]
}
```

## Requirements

### Prerequisites
- Accounts must have **saved Authenticators** in the system
- Accounts must exist in the `GoogleAccount` database table
- Domain must be valid and accessible by the accounts

### Limitations
- Maximum 1000 users per account
- Maximum 10 accounts processed in parallel
- Password must be at least 8 characters
- Domain must be valid format (e.g., `example.com`)

## Error Handling

### Account-Level Errors
- **Account not found**: Account doesn't exist in database
- **Authentication failed**: No saved Authenticator or invalid credentials
- **Service unavailable**: Cannot get Google API service

### User-Level Errors
- **Duplicate user**: Email already exists
- **Domain limit**: Domain user limit reached
- **Invalid domain**: Domain not found or invalid

All errors are logged and displayed in the results, allowing partial success scenarios.

## UI Components

### Main Section
- **Location**: Top of Tab 2
- **Style**: Blue-bordered card for prominence
- **Button**: "Manage Bulk Accounts" opens modal

### Modal/Popup
- **Size**: 700px max width
- **Fields**: 
  - Accounts textarea (8 rows)
  - Users per account input
  - Domain input
  - Password input
- **Actions**: Start Bulk Creation, Cancel

### Results Section
- **Display**: Shows after completion
- **Format**: Textarea with `user:password` format
- **Features**: 
  - Read-only textarea
  - Copy button
  - Summary statistics
  - Auto-scroll to results

## Technical Implementation

### Backend (`app.py`)
- **Endpoint**: `/api/bulk-create-account-users`
- **Authentication**: Uses `authenticate_without_session()` for parallel auth
- **Parallel Processing**: `ThreadPoolExecutor` with max 10 workers
- **User Generation**: Random name generation with duplicate prevention

### Frontend (`dashboard.html`)
- **Modal**: Custom modal with form inputs
- **JavaScript**: 
  - `openBulkAccountModal()`: Opens modal
  - `closeBulkAccountModal()`: Closes modal
  - `executeBulkAccountCreation()`: Handles API call
  - `displayBulkAccountResults()`: Displays results
  - `copyBulkAccountResults()`: Copies to clipboard

### Authentication
- Uses existing `authenticate_without_session()` function
- Retrieves Authenticators from saved files
- Creates Google API service for each account
- Handles authentication failures gracefully

## Usage Example

1. **Navigate** to Dashboard → User Create/Delete/Domain tab
2. **Click** "Manage Bulk Accounts" button
3. **Enter** account emails (one per line):
   ```
   admin1@example.com
   admin2@example.com
   admin3@example.com
   ```
4. **Set** users per account: `10`
5. **Enter** domain: `example.com`
6. **Enter** password: `SecurePass123`
7. **Click** "Start Bulk Creation"
8. **Wait** for processing (progress bar shows status)
9. **View** results in copyable format
10. **Copy** all `user:password` pairs with one click

## Benefits

✅ **Time Saving**: Process multiple accounts simultaneously
✅ **Automated**: No manual authentication needed
✅ **Parallel**: All accounts processed at the same time
✅ **Copyable**: Easy extraction of created users
✅ **Error Handling**: Clear error messages for troubleshooting
✅ **Scalable**: Handles up to 10 accounts in parallel

## Files Modified

1. **`templates/dashboard.html`**:
   - Added Bulk Account Management section
   - Added modal/popup for configuration
   - Added JavaScript functions
   - Added results display section

2. **`app.py`**:
   - Added `/api/bulk-create-account-users` endpoint
   - Implemented parallel authentication
   - Implemented parallel user creation
   - Added error handling and logging

## Future Enhancements

- [ ] Add progress updates for individual accounts
- [ ] Add ability to delete users in bulk
- [ ] Add CSV export option
- [ ] Add retry mechanism for failed authentications
- [ ] Add batch processing for very large account lists

