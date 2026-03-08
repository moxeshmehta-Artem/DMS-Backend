# JPA Auditing Flow: How & Why It Works

This document explains how your project **automatically tracks WHO created/modified a record and WHEN** — without writing a single line of manual code in your services.

---

## 🤔 Why Do We Need Auditing?

Imagine this scenario in a hospital:

> Patient "Artem" complains that someone changed his diet plan. The admin asks:
> **"Who changed it? When was it changed?"**

**Without auditing** → You have no idea. There's no record.

**With auditing** → You check the database:

| id  | breakfast      | **created_by** | **created_at**   | **last_modified_by** | **updated_at**       |
| --- | -------------- | -------------- | ---------------- | -------------------- | -------------------- |
| 7   | Oats with milk | dr_sarah       | 2026-03-01 09:00 | **dr_priya**         | **2026-03-05 14:30** |

Now you know: **Dr. Priya** modified it on **March 5th at 2:30 PM**. Problem solved.

---

## 🏗️ The 4 Files That Make Auditing Work

```
┌────────────────────────────────────┐
│  1. JpaConfig.java                 │  ← Turns ON auditing for the entire app
│     @EnableJpaAuditing             │
└───────────────┬────────────────────┘
                │ "Who is the current user?"
                ▼
┌────────────────────────────────────┐
│  2. AuditorAwareImpl.java          │  ← Answers: "It's 'dr_sarah'" (from JWT)
│     getCurrentAuditor()            │
└───────────────┬────────────────────┘
                │ provides username to
                ▼
┌────────────────────────────────────┐
│  3. BaseEntity.java                │  ← Defines the 6 audit columns
│     @CreatedBy, @CreatedDate, etc  │
└───────────────┬────────────────────┘
                │ inherited by
                ▼
┌────────────────────────────────────┐
│  4. All Entities                   │  ← User, Appointment, Vitals,
│     extends BaseEntity             │     DietPlan, DietitianSchedule
└────────────────────────────────────┘
```

---

## 📄 File 1: `JpaConfig.java` — The ON Switch

```java
@Configuration
@EnableJpaAuditing(auditorAwareRef = "auditorProvider")
public class JpaConfig {

    @Bean
    public AuditorAware<String> auditorProvider() {
        return new AuditorAwareImpl();
    }
}
```

### Why?

| Code                                  | Purpose                                                                                                               |
| :------------------------------------ | :-------------------------------------------------------------------------------------------------------------------- |
| `@EnableJpaAuditing`                  | **Activates** Spring Data JPA's auditing feature globally. Without this, `@CreatedDate`, `@CreatedBy` etc. do nothing |
| `auditorAwareRef = "auditorProvider"` | Tells Spring: "When you need to know WHO the current user is, use this bean"                                          |
| `return new AuditorAwareImpl()`       | Creates the bean that answers "who is the current user?"                                                              |

**Without this file** → All `@CreatedBy` and `@LastModifiedBy` fields would be `null`.

---

## 📄 File 2: `AuditorAwareImpl.java` — The "Who Is Logged In?" Detector

```java
@Component
public class AuditorAwareImpl implements AuditorAware<String> {

    @Override
    public Optional<String> getCurrentAuditor() {
        // Step 1: Get the current security context
        Authentication authentication = SecurityContextHolder
                .getContext().getAuthentication();

        // Step 2: If no user is logged in (e.g., system startup, registration)
        if (authentication == null || !authentication.isAuthenticated()
                || authentication.getPrincipal().equals("anonymousUser")) {
            return Optional.of("SYSTEM");
        }

        // Step 3: Return the logged-in username
        return Optional.ofNullable(authentication.getName());
    }
}
```

### Why? — Line-by-Line

| Code                                                     | Purpose                                                                                          | Example                                      |
| :------------------------------------------------------- | :----------------------------------------------------------------------------------------------- | :------------------------------------------- |
| `SecurityContextHolder.getContext().getAuthentication()` | Gets the **currently logged-in user's info** from the JWT token that was set by `JwtInterceptor` | Returns auth object with `username=dr_sarah` |
| `authentication == null`                                 | Handles edge case: no user context exists (e.g., app startup)                                    | Returns `"SYSTEM"`                           |
| `"anonymousUser"`                                        | Spring's default for unauthenticated requests (e.g., registration/login endpoints)               | Returns `"SYSTEM"`                           |
| `authentication.getName()`                               | Returns the **username** string from the JWT token                                               | `"dr_sarah"`                                 |

### How Does the Username Get Into SecurityContext?

This is done by `JwtInterceptor.java` — **before** any controller method runs:

```java
// JwtInterceptor.java (line 52-62)
String username = jwtUtils.getUserNameFromJwtToken(token);  // "dr_sarah"
String role = jwtUtils.getRoleFromJwtToken(token);          // "ROLE_DIETITIAN"

// Store in Spring Security context → AuditorAwareImpl reads from HERE
UsernamePasswordAuthenticationToken authenticationToken =
    new UsernamePasswordAuthenticationToken(
        username, null, Collections.singletonList(new SimpleGrantedAuthority(role)));
SecurityContextHolder.getContext().setAuthentication(authenticationToken);
```

### Connection Chain:
```
JWT Token ("Bearer eyJ...")
    → JwtInterceptor extracts username ("dr_sarah")
        → Stores in SecurityContextHolder
            → AuditorAwareImpl reads from SecurityContextHolder
                → JPA uses it to fill @CreatedBy / @LastModifiedBy
```

---

## 📄 File 3: `BaseEntity.java` — The 6 Audit Columns

```java
@Getter
@Setter
@MappedSuperclass
@EntityListeners(AuditingEntityListener.class)
public abstract class BaseEntity {

    // ═══ WHEN fields (auto-set by Spring) ═══

    @CreatedDate
    @Column(name = "created_at", nullable = false, updatable = false)
    private LocalDateTime createdAt;

    @LastModifiedDate
    @Column(name = "updated_at", nullable = false)
    private LocalDateTime updatedAt;

    // ═══ WHO fields (auto-set by AuditorAwareImpl) ═══

    @CreatedBy
    @Column(name = "created_by", nullable = false, updatable = false)
    private String createdBy;

    @LastModifiedBy
    @Column(name = "last_modified_by", nullable = false)
    private String lastModifiedBy;

    // ═══ SOFT DELETE fields (set manually in code) ═══

    @Column(name = "deleted", nullable = false)
    private boolean deleted = false;

    @Column(name = "deleted_at")
    private LocalDateTime deletedAt;
}
```

### Why Each Annotation?

| Annotation                                       | What It Does                                                                 | When It Fires                       | Value Set                                               |
| :----------------------------------------------- | :--------------------------------------------------------------------------- | :---------------------------------- | :------------------------------------------------------ |
| `@CreatedDate`                                   | Auto-fills `created_at`                                                      | Only on **first save** (INSERT)     | `LocalDateTime.now()` e.g. `2026-03-05T14:30:00`        |
| `@LastModifiedDate`                              | Auto-fills `updated_at`                                                      | On **every save** (INSERT + UPDATE) | `LocalDateTime.now()`                                   |
| `@CreatedBy`                                     | Auto-fills `created_by`                                                      | Only on **first save**              | Username from `AuditorAwareImpl` e.g. `"dr_sarah"`      |
| `@LastModifiedBy`                                | Auto-fills `last_modified_by`                                                | On **every save**                   | Username from `AuditorAwareImpl`                        |
| `updatable = false`                              | Prevents overwriting on updates                                              | —                                   | `created_at` and `created_by` are LOCKED after creation |
| `@MappedSuperclass`                              | This is NOT a table itself — its columns are **inherited** by child entities | —                                   | Adds columns to `users`, `appointments`, `vitals`, etc. |
| `@EntityListeners(AuditingEntityListener.class)` | Tells JPA to **listen** for save events and trigger auditing                 | —                                   | Required for `@CreatedDate` etc. to work                |

### Why `updatable = false`?

This protects the **original creation record**. Without it:

```
Original: created_by = "dr_sarah", created_at = March 1
After update: created_by = "dr_priya" ← WRONG! Sarah created it, not Priya
```

With `updatable = false`, `created_by` and `created_at` are **permanently locked** after the first save.

---

## 📄 File 4: All 5 Entities That Inherit Auditing

Every entity in your project extends `BaseEntity`, so every table automatically gets the 6 audit columns:

```java
public class User extends BaseEntity { ... }
public class Appointment extends BaseEntity { ... }
public class Vitals extends BaseEntity { ... }
public class DietPlan extends BaseEntity { ... }
public class DietitianSchedule extends BaseEntity { ... }
```

This means the `users` table actually looks like:

| Column             | Source                     |
| :----------------- | :------------------------- |
| `id`               | From `User.java`           |
| `username`         | From `User.java`           |
| `password`         | From `User.java`           |
| `email`            | From `User.java`           |
| ...                | ...                        |
| `created_at`       | ✨ From `BaseEntity` (auto) |
| `updated_at`       | ✨ From `BaseEntity` (auto) |
| `created_by`       | ✨ From `BaseEntity` (auto) |
| `last_modified_by` | ✨ From `BaseEntity` (auto) |
| `deleted`          | From `BaseEntity` (manual) |
| `deleted_at`       | From `BaseEntity` (manual) |

---

## 🔄 Complete Flow: What Happens When a Record Is Saved

### Example: Dietitian "dr_sarah" creates a diet plan

```
1. dr_sarah logs in → gets JWT token containing username="dr_sarah"

2. Frontend sends POST /api/diet-plans with body { breakfast: "Oats" }
   Header: Authorization: Bearer eyJ...

3. JwtInterceptor runs BEFORE the controller:
   ├─ Extracts "dr_sarah" from JWT token
   └─ Stores in SecurityContextHolder

4. Controller → Service → repository.save(dietPlan)

5. JPA detects this is a NEW entity (INSERT):
   ├─ @CreatedDate  → sets created_at  = 2026-03-05T14:30:00
   ├─ @LastModifiedDate → sets updated_at = 2026-03-05T14:30:00
   ├─ @CreatedBy → calls AuditorAwareImpl.getCurrentAuditor()
   │               → reads SecurityContextHolder → "dr_sarah"
   │               → sets created_by = "dr_sarah"
   └─ @LastModifiedBy → sets last_modified_by = "dr_sarah"

6. SQL generated:
   INSERT INTO diet_plans (breakfast, created_at, updated_at,
       created_by, last_modified_by, deleted)
   VALUES ('Oats', '2026-03-05 14:30:00', '2026-03-05 14:30:00',
       'dr_sarah', 'dr_sarah', false);
```

### Later: Dietitian "dr_priya" updates the same plan

```
1. dr_priya logs in → JWT contains username="dr_priya"

2. Frontend sends PUT /api/diet-plans/7 with body { breakfast: "Muesli" }

3. JwtInterceptor stores "dr_priya" in SecurityContextHolder

4. Service loads existing plan → modifies it → repository.save(dietPlan)

5. JPA detects this is an EXISTING entity (UPDATE):
   ├─ @CreatedDate     → NOT changed (updatable = false) ✅
   ├─ @LastModifiedDate → updated_at = 2026-03-06T10:00:00
   ├─ @CreatedBy       → NOT changed (updatable = false) ✅
   └─ @LastModifiedBy  → last_modified_by = "dr_priya"

6. SQL generated:
   UPDATE diet_plans
   SET breakfast = 'Muesli',
       updated_at = '2026-03-06 10:00:00',
       last_modified_by = 'dr_priya'
   WHERE id = 7;
   -- Notice: created_at and created_by are NOT in the UPDATE
```

### Database after both operations:

| id  | breakfast | created_by | created_at       | last_modified_by | updated_at           |
| --- | --------- | ---------- | ---------------- | ---------------- | -------------------- |
| 7   | Muesli    | dr_sarah   | 2026-03-05 14:30 | **dr_priya**     | **2026-03-06 10:00** |

Now you can see: **Sarah created it, Priya modified it**.

---

## 🎯 Summary: Why We Need Each Piece

| File                               | Without It                                                                    | With It                                                                         |
| :--------------------------------- | :---------------------------------------------------------------------------- | :------------------------------------------------------------------------------ |
| `JpaConfig.java`                   | Auditing is turned OFF — all annotations are ignored                          | Auditing is turned ON globally                                                  |
| `AuditorAwareImpl.java`            | JPA doesn't know WHO the current user is → `created_by` is null               | Reads username from JWT via SecurityContext                                     |
| `BaseEntity.java`                  | Every entity would need to manually define audit columns (duplicated code)    | Define once, inherited by all 5 entities                                        |
| `JwtInterceptor.java` (line 60-62) | Username only exists in the HTTP request — `AuditorAwareImpl` can't access it | Puts username into `SecurityContextHolder` where `AuditorAwareImpl` can read it |

### Benefits of Auditing:
1. **Accountability** — Know exactly who created/modified each record
2. **Debugging** — Track when data changed for troubleshooting
3. **Compliance** — Healthcare systems often require an audit trail
4. **Zero manual effort** — Developers never need to write `entity.setCreatedBy(username)` — it's fully automatic
