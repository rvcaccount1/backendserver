# Firestore Database Structure

This document describes the Firestore collections and data structure used by both the Web Admin Dashboard and Android Mobile App.

## Shared Collections

Both the web application and Android app use the same Firestore database (`openvax-654321`) and share the following collections:

### 1. `vaccineStock` Collection
**Purpose**: Stores vaccine inventory/stock data
**Used by**: Web Admin Dashboard (for management) and Android App (for viewing)

**Document Structure**:
```javascript
{
  name: string,              // Vaccine name (e.g., "COVID-19 Vaccine")
  batchNumber: string,       // Batch number
  quantity: number,          // Available quantity
  status: string,            // "adequate" | "moderate" | "critical"
  locationAddress: string,   // Storage location
  manufacturer: string,      // Manufacturer name
  manufactureDate: string,   // Manufacture date
  expiryDate: string,        // Expiry date
  isArchived: boolean,       // Archive flag
  createdAt: Timestamp,      // Creation timestamp
  createdBy: {               // Creator info
    uid: string,
    email: string
  }
}
```

### 2. `users` Collection
**Purpose**: Stores user accounts, profiles, and vaccination history
**Used by**: Web Admin Dashboard (for user management) and Android App (for user profiles and vaccination records)

**Document Structure**:
```javascript
{
  // User Profile
  firstName: string,
  middleName: string,
  lastName: string,
  fullName: string,
  email: string,
  role: string,              // "admin" | "employee" | "user"
  isActive: boolean,         // Account status
  
  // Branch Information (for admin/employee)
  branchName: string,        // Branch/location name
  branchlocation: string,    // Branch location
  
  // Vaccination History (for all users, including Android app users)
  vaccineHistory: [
    {
      vaccine: string,       // Vaccine name (e.g., "COVID-19 Vaccine")
      date: string,          // Vaccination date
      location: string       // Vaccination location
    }
  ],
  
  // Other fields
  createdAt: Timestamp,
  // ... other profile fields
}
```

### 3. `announcements` Collection
**Purpose**: Stores public announcements
**Used by**: Web Admin Dashboard (for management) and Android App (for viewing)

### 4. `sites` Collection
**Purpose**: Stores vaccination site locations
**Used by**: Web Admin Dashboard (for management) and Android App (for viewing)

### 5. `vaccineInfo` Collection
**Purpose**: Stores vaccine information and details
**Used by**: Web Admin Dashboard (for management) and Android App (for viewing)

### 6. `auditLogs` Collection
**Purpose**: Stores audit trail of all actions
**Used by**: Web Admin Dashboard only (admin monitoring)

## Dashboard Data Sources

The Admin Dashboard (`/admin/dashboard`) fetches real-time data from:

1. **Total Vaccine Stock**: Sum of all `quantity` fields from `vaccineStock` collection (where `isArchived == false`)
2. **Active Branches**: Count of unique `branchName` from `users` collection (where `role` is "admin" or "employee" and `isActive == true`)
3. **Critical Stock Alerts**: Count of documents in `vaccineStock` collection (where `status == "critical"` and `isArchived == false`)
4. **Total Vaccinations**: Count of all records in `vaccineHistory` arrays from all users in `users` collection
5. **Vaccinations by Type**: Aggregated count of vaccinations grouped by vaccine name from all users' `vaccineHistory`

## Android App Integration

The Android app should:
1. Use the same Firebase project configuration (`openvax-654321`)
2. Read from the same collections (`vaccineStock`, `users`, `announcements`, `sites`, `vaccineInfo`)
3. Write vaccination history to `users/{userId}/vaccineHistory` array
4. Ensure data structure matches the web app structure

## Real-time Updates

All data is fetched using Firestore `onSnapshot` listeners, which means:
- Changes made in the web app are immediately visible in the Android app
- Changes made in the Android app are immediately visible in the web dashboard
- No manual refresh is needed - data updates automatically

## Notes

- The dashboard shows data from ALL users, including Android app users
- Vaccination history entered in the Android app is automatically included in the dashboard statistics
- Vaccine stock managed by admins in the web app is visible to Android app users
- All data is synchronized in real-time across both platforms

