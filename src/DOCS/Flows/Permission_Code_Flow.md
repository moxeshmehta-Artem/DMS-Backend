# Permission Code Flow: Frontend Logic Documentation

This document explains the automated code flow that determines what a user can see and do in the frontend based on their **Role**.

---

## 🏗️ Overview: The Permission Chain

```
 LOGIN (JWT) ──▶ Role Enum ──▶ PERMISSIONS Constant ──▶ Dashboard Component ──▶ UI Display (*ngIf)
```

| Step              | File                       | Purpose                                                                                     |
| :---------------- | :------------------------- | :------------------------------------------------------------------------------------------ |
| **1. Identity**   | `auth.service.ts`          | Decodes the JWT and maps the backend role (e.g., `ROLE_ADMIN`) to the frontend `Role` enum. |
| **2. Definition** | `permissions.ts`           | A centralized constant that defines exactly what "Capabilities" each role has.              |
| **3. Loading**    | `dashboard.component.ts`   | Imports the constant and loads the specific rules for the logged-in user's role.            |
| **4. Rendering**  | `dashboard.component.html` | Uses `*ngIf` to show or hide buttons/chips based on those rules.                            |

---

## 🟢 Step 1: Role Identification

When a user logs in, the `AuthService` converts the backend role string into a frontend **Role Enum**.

```typescript
// auth.service.ts
private mapBackendRoleToEnum(roles: string[]): Role {
    const roleStr = roles[0].replace('ROLE_', ''); // "ADMIN", "DIETITIAN", etc.
    if (roleStr === 'ADMIN') return Role.Admin;
    return Role.Patient; // Default fallback
}
```

---

## 🟡 Step 2: Centralized Permissions

**File**: `core/constants/permissions.ts`

Instead of writing `if (role === 'ADMIN')` everywhere, we define a static map of **Capabilities**.

```typescript
export const PERMISSIONS = {
    [Role.Admin]: {
        canAddDietitian: true,
        canManageUsers: true
    },
    [Role.Dietitian]: {
        canViewPatients: true,
        canAddDietPlan: true
    }
};
```

---

## 🔵 Step 3: Component Integration

**File**: `dashboard.component.ts`

When the Dashboard initializes, it asks the `AuthService` for the current role and looks up the corresponding permission object.

```typescript
// dashboard.component.ts
ngOnInit() {
    const role = this.authService.getUserRole();
    if (role) {
        // Look up the specific "capabilities" object for this role
        this.permissions = PERMISSIONS[role] || {};
        
        // Also look up the "menu cards" for this role
        this.menuItems = MENU_ITEMS[role] || [];
    }
}
```

---

## 🔴 Step 4: The UI Display

**File**: `dashboard.component.html`

The template simply checks the `permissions` object. It doesn't care *why* the user has permission; it just checks the flag.

```html
<!-- Only shows if the loaded permission object has canRegisterPatient = true -->
<p-chip *ngIf="permissions.canRegisterPatient" label="Register Patient"></p-chip>

<!-- Dynamic Menu Cards -->
<div *ngFor="let item of menuItems">
    <!-- Renders "Add Dietitian" or "Book Appointment" cards -->
</div>
```

---

## 🎯 Why This Flow is Better

1.  **Readability**: HTML elements say exactly what they are doing (`*ngIf="canAddDietPlan"`), not which role has them.
2.  **Scalability**: If you add a new role (e.g., `SUPER_ADMIN`), you only need to add one entry in `permissions.ts`. You don't have to touch 20 Different HTML files.
3.  **Syncing**: The `MENU_ITEMS` (large dashboard cards) and the `PERMISSIONS` (small UI buttons/chips) both use the same **Role Engine**, ensuring the UI is consistent.
4.  **Security**: While the frontend hides things for a better UX, the **Backend** still verifies the role via `@RequireRole` to ensure true security.

---

## 🛠️ How to Add a New Capability

1.  **Constant**: Add a new flag (e.g., `canExportReport: true`) to the roles in `permissions.ts`.
2.  **HTML**: Use it anywhere in your templates: `*ngIf="permissions.canExportReport"`.
3.  **Done!** No need to change any logic in your `.ts` components.
