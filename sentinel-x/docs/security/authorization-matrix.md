# Sentinel-X Security: Role-Based Access Control (RBAC) Authorization Matrix

## 1. Access Control Philosophy

Sentinel-X enforces **Least-Privilege Role-Based Access Control (RBAC)**. Permissions are verified strictly on the server side using FastAPI dependency injection (`RoleChecker`), ensuring that client-side UI manipulation cannot bypass operational boundaries.

### Role Definitions
1. **ADMIN**: Super-operator role responsible for system configuration, user provisioning, model promotion, and global security audit reviews.
2. **ANALYST**: Core SOC responder role with operational privileges to ingest packet captures, triage alerts, adjust incident statuses, submit ML feedback, and generate reports.
3. **VIEWER**: Executive and audit observer role with read-only visibility into dashboard visualizations, security metrics, and incident summaries.

---

## 2. Complete Permissions Matrix

| Resource Domain | Endpoint / Action | Method | VIEWER | ANALYST | ADMIN | Enforced By |
|:---|:---|:---:|:---:|:---:|:---:|:---|
| **Authentication** | `/api/v1/auth/login` | POST | 🟢 Public | 🟢 Public | 🟢 Public | RateLimiter |
| | `/api/v1/auth/refresh` | POST | 🟢 Public | 🟢 Public | 🟢 Public | Cookie Verification |
| | `/api/v1/auth/logout` | POST | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| | `/api/v1/auth/me` | GET | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| **User Administration** | `/api/v1/users` (List) | GET | 🔴 403 | 🔴 403 | 🟢 Allowed | `RoleChecker(["ADMIN"])` |
| | `/api/v1/users` (Create) | POST | 🔴 403 | 🔴 403 | 🟢 Allowed | `RoleChecker(["ADMIN"])` |
| | `/api/v1/users/{id}` (Get) | GET | 🔴 403 | 🔴 403 | 🟢 Allowed | `RoleChecker(["ADMIN"])` |
| | `/api/v1/users/{id}` (Update) | PATCH | 🔴 403 | 🔴 403 | 🟢 Allowed | `RoleChecker(["ADMIN"])` |
| | `/api/v1/users/{id}` (Delete) | DELETE | 🔴 403 | 🔴 403 | 🟢 Allowed | `RoleChecker(["ADMIN"])` |
| **Ingestion Pipeline** | `/api/v1/ingestion/upload` | POST | 🔴 403 | 🟢 Allowed | 🟢 Allowed | `RoleChecker(["ADMIN", "ANALYST"])` |
| | `/api/v1/ingestion/stream` | POST | 🔴 403 | 🟢 Allowed | 🟢 Allowed | `RoleChecker(["ADMIN", "ANALYST"])` |
| **Detections & AI** | `/api/v1/detections` | GET | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| | `/api/v1/detections/{id}` | GET | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| | `/api/v1/detections/{id}/shap`| GET | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| | `/api/v1/detections/{id}/feedback` | POST | 🔴 403 | 🟢 Allowed | 🟢 Allowed | `RoleChecker(["ADMIN", "ANALYST"])` |
| **Incident Management**| `/api/v1/incidents` | GET | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| | `/api/v1/incidents/{id}` | GET | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| | `/api/v1/incidents/{id}/status` | PATCH | 🔴 403 | 🟢 Allowed | 🟢 Allowed | `RoleChecker(["ADMIN", "ANALYST"])` |
| | `/api/v1/incidents/{id}/events` | POST | 🔴 403 | 🟢 Allowed | 🟢 Allowed | `RoleChecker(["ADMIN", "ANALYST"])` |
| **Threat Intelligence**| `/api/v1/threat-intel/lookup` | POST | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| | `/api/v1/threat-intel/sync` | POST | 🔴 403 | 🔴 403 | 🟢 Allowed | `RoleChecker(["ADMIN"])` |
| **Dashboard Metrics** | `/api/v1/dashboard/metrics` | GET | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| | `/api/v1/dashboard/timeseries`| GET | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| **Reporting** | `/api/v1/reports` (List) | GET | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| | `/api/v1/reports/generate` | POST | 🔴 403 | 🟢 Allowed | 🟢 Allowed | `RoleChecker(["ADMIN", "ANALYST"])` |
| | `/api/v1/reports/{id}/download` | GET | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| **Model Registry** | `/api/v1/models` (List) | GET | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |
| | `/api/v1/models/promote` | POST | 🔴 403 | 🔴 403 | 🟢 Allowed | `RoleChecker(["ADMIN"])` |
| **Audit Logs** | `/api/v1/audit-logs` | GET | 🔴 403 | 🟢 Allowed | 🟢 Allowed | `RoleChecker(["ADMIN", "ANALYST"])` |
| **WebSocket Alerts** | `/api/v1/ws/alerts` | WS | 🟢 Allowed | 🟢 Allowed | 🟢 Allowed | Bearer Token Auth |

---

## 3. Server-Side Enforcement Implementation

Authorization boundaries are enforced via Python class decorators and FastAPI dependency injection:

```python
class RoleChecker:
    def __init__(self, allowed_roles: List[str]):
        self.allowed_roles = allowed_roles

    def __call__(self, current_user: User = Depends(get_current_user)) -> User:
        if current_user.role.name not in self.allowed_roles:
            raise AuthorizationError(
                message=f"Role '{current_user.role.name}' does not have sufficient privileges",
                details={
                    "required_roles": self.allowed_roles,
                    "user_role": current_user.role.name
                }
            )
        return current_user
```

When an unauthorized user attempts an operation, the API halts execution immediately, commits no database mutations, logs a security warning, and issues an HTTP 403 with standard code `AUTHORIZATION_DENIED`.

