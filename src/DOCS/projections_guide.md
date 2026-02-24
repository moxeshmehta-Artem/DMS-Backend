# Spring Data JPA Projections: The "Old Way" vs. "New Way"

When building features like selection dropdowns or summary lists, you have two choices. Here is how they compare.

## 1. The "Old Way": Entity -> DTO Mapping
In this approach, you fetch the entire object from the database and then transform it.

### Code Example:
```java
// 1. Fetch ALL columns (including password, role, dob, etc.)
User user = userRepository.findById(id).get(); 

// 2. Manually map to a DTO (or use a mapper)
UserDTO dto = new UserDTO(user.getId(), user.getFirstName(), user.getLastName());
```

### The Cost:
- **Select * Query**: SQL fetches every single column, even if you only need 3.
- **Memory Waste**: Spring/Hibernate creates a heavy "Managed Entity" object in memory.
- **Security Risk**: You accidentally pull sensitive data (like password hashes) into memory before discarding them.

---

## 2. The "New Way": Projections
In this approach, the database only fetches exactly what you asked for.

### Code Example:
```java
// 1. Repository defines the specific fields
public interface UserSummary {
    Long getId();
    String getFirstName();
    String getLastName();
}

// 2. SQL only fetches 3 columns
List<UserSummary> users = userRepository.findAllProjectedBy();
```

### The Benefits:
- **Optimized SQL**: SQL becomes `SELECT id, first_name, last_name FROM users`.
- **Zero Overhead**: No heavy Entity objects are created; Spring creates a lightweight Proxy.
- **Speed**: In tables with 50+ columns, Projections can be **2x to 5x faster** than fetching Entities.

---

## Comparison Table

| Feature | Entity + DTO (Old Way) | Projection (New Way) |
| :--- | :--- | :--- |
| **Database Load** | **High** (Fetches all columns) | **Low** (Fetches specific columns) |
| **Java Memory** | **Heavy** (Full object graph) | **Light** (Simple interface proxy) |
| **Development Speed**| Slower (Needs DTO + Mapper) | Faster (Just define an interface) |
| **Best For...** | Editing/Updating data | **Read-only lists & Dropdowns** |

### Visualization of Efficiency

````carousel
```sql
/* OLD WAY */
SELECT id, username, password, email, 
       first_name, last_name, role, gender, 
       date_of_birth, age, phone... 
FROM users;
```
<!-- slide -->
```sql
/* PROJECTION WAY */
SELECT id, first_name, last_name 
FROM users;
```
````

> [!IMPORTANT]
> Use **Projections** for high-traffic "Read Only" pages. Use **Entities** only when you need to "Save" or "Update" data.
