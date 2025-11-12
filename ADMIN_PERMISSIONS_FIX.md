# Admin Permissions Fix

## Issue
Admin user creation was failing with the error:
```
🔒 ADMIN PERMISSION ERROR: User created but role assignment failed: 
<HttpError 403 when requesting https://admin.googleapis.com/admin/directory/v1/customer/my_customer/roleassignments?alt=json 
returned "Request had insufficient authentication scopes.". 
Details: "[{'message': 'Insufficient Permission', 'domain': 'global', 'reason': 'insufficientPermissions'}]">
```

## Root Cause
The OAuth scopes were insufficient for admin role management. The app only had:
- `https://www.googleapis.com/auth/admin.directory.user`
- `https://www.googleapis.com/auth/admin.directory.domain`

But admin role assignment requires additional scopes.

## Solution
Updated OAuth scopes in both `config.py` and `core_logic.py` to include:

### New Scopes Added:
- `https://www.googleapis.com/auth/admin.directory.rolemanagement` - For assigning admin roles
- `https://www.googleapis.com/auth/admin.directory.orgunit` - For organizational unit management
- `https://www.googleapis.com/auth/admin.directory.group` - For group management

### Files Modified:
1. **config.py** - Updated `SCOPES` list
2. **core_logic.py** - Updated OAuth flow scopes

## Required Action
**Users must re-authenticate their Google accounts** to get the new permissions:

1. Go to the dashboard
2. Click "Add New Account" or re-authenticate existing account
3. Complete the OAuth flow with new permissions
4. Try creating admin users again

## Expected Result
After re-authentication, admin user creation should work properly with:
- ✅ User creation successful
- ✅ Admin role assignment successful
- ✅ No more permission errors

## Admin Roles Supported
- SUPER_ADMIN
- USER_MANAGEMENT_ADMIN
- HELP_DESK_ADMIN
- SERVICE_ADMIN
- BILLING_ADMIN
- SECURITY_ADMIN

## Technical Details
The Google Admin SDK requires specific scopes for role management operations. The `roleAssignments().insert()` method needs the `admin.directory.rolemanagement` scope to assign admin roles to users.
