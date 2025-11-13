# Python Banking - Comprehensive Vulnerability Test Codebase

## Overview
8 vulnerabilities with 4-6 function attack paths testing AI-SAST analyzer classification accuracy.

## Vulnerability Catalog

### VULN 1: SQL Injection - MUST_FIX ✅ True Positive
**Location**: GET /api/accounts/search

**Attack Path (5 functions)**:
```
1. search_accounts()              [controllers/account_controller.py:10]
   └→ 2. account_service.search_by_name(name)      [services/account_service.py:13]
       └→ 3. processor.process_search_term(name)   [utils/input_processor.py:2]
           └→ 4. repository.search_accounts_raw()  [repositories/account_repository.py:8]
               └→ 5. db.execute_raw_query(query)   [utils/database_helper.py:7]
                   └→ cursor.execute(query) [SINK]
```

**Why Must Fix**: Direct SQL injection, no sanitization, no protection.

---

### VULN 2: SQL Injection - FALSE_POSITIVE (Sanitized) ✅ Parameterized Query
**Location**: GET /api/accounts/find

**Attack Path (5 functions)**:
```
1. find_account()                              [controllers/account_controller.py:16]
   └→ 2. account_service.find_by_id_safe(id)            [services/account_service.py:18]
       └→ 3. validator.validate_numeric(id)             [services/validation_service.py:11]
           └→ 4. repository.find_by_id_parameterized()  [repositories/account_repository.py:13]
               └→ 5. db.execute_parameterized_query()   [utils/database_helper.py:12]
                   └→ cursor.execute(query, params) [SINK - SAFE]
```

**Why False Positive**: Uses parameterized query - SQL injection impossible.
**Subcategory**: 2A - Direct Sanitization

---

### VULN 3: SQL Injection - FALSE_POSITIVE (Sanitized) ✅ Allowlist Validation
**Location**: GET /api/accounts/lookup

**Attack Path (5 functions)**:
```
1. lookup_account()                             [controllers/account_controller.py:22]
   └→ 2. account_service.lookup_by_type(type)         [services/account_service.py:23]
       └→ 3. validator.validate_account_type(type)    [services/validation_service.py:6]
           [VALIDATOR: Strict allowlist - only 4 values allowed]
           └→ 4. repository.lookup_by_validated_type() [repositories/account_repository.py:18]
               └→ 5. db.execute_raw_query(query)       [utils/database_helper.py:7]
                   └→ cursor.execute(query) [SINK - SAFE]
```

**Why False Positive**: Strict allowlist validation (only 4 predefined values allowed).
**Subcategory**: 2B - Validation-Based

---

### VULN 4: SQL Injection - FALSE_POSITIVE (Protected) ✅ Defense-in-Depth
**Location**: POST /api/accounts/admin/search

**Attack Path (4 functions + 3 security layers)**:
```
[@admin_required]      - Layer 1: Admin role required
[@csrf_protected]      - Layer 2: CSRF token validation
[@rate_limit(10, 60)]  - Layer 3: 10 requests per 60 seconds

1. admin_search()                               [controllers/account_controller.py:31]
   └→ 2. account_service.admin_raw_search(query)      [services/account_service.py:28]
       └→ 3. repository.admin_search_raw(query)       [repositories/account_repository.py:23]
           └→ 4. db.execute_raw_query(query)          [utils/database_helper.py:7]
               └→ cursor.execute(query) [SINK - PROTECTED]
```

**Why False Positive**: Multiple security layers make exploitation impractical.
**Subcategory**: 3B - Defense-in-Depth

---

### VULN 5: SQL Injection - MUST_FIX ✅ Mixed Paths (Live + Dead)
**Location**: GET /api/accounts/report

**CRITICAL TEST**: This vulnerability has BOTH dead and live paths!

**Path A - LIVE VULNERABLE (4 functions)**:
```
1. generate_report(type='detailed')             [controllers/account_controller.py:38]
   [if report_type == 'detailed']  <-- LIVE PATH
   └→ 2. account_service.generate_detailed_report(id)  [services/account_service.py:32]
       └→ 3. repository.get_detailed_report(id)         [repositories/account_repository.py:28]
           └→ 4. db.execute_raw_query(query)            [utils/database_helper.py:7]
               └→ cursor.execute(query) [SINK - VULNERABLE]
```

**Path B - DEAD CODE (4 functions)**:
```
1. generate_report(type='legacy')               [controllers/account_controller.py:38]
   [if report_type == 'legacy']  <-- DEAD PATH (never used)
   └→ 2. account_service.generate_legacy_report(id)    [services/account_service.py:36]
       └→ 3. repository.get_legacy_report(id)           [repositories/account_repository.py:33]
           └→ 4. db.execute_raw_query(query)            [utils/database_helper.py:7]
               └→ cursor.execute(query) [SINK - DEAD CODE]
```

**Why Must Fix**: At least ONE path (Path A) is exploitable - live path overrides dead path!
**Expected**: must_fix with path-level assessment showing both VULNERABLE and DEAD_CODE paths.

---

### VULN 6: SQL Injection - FALSE_POSITIVE (Dead Code) ✅ Unreachable Function
**Location**: unused_legacy_search() (not a route)

**Attack Path (4 functions - ALL DEAD)**:
```
1. unused_legacy_search()  [NOT REGISTERED AS ROUTE]   [controllers/account_controller.py:49]
   └→ 2. account_service.legacy_search(query)          [services/account_service.py:40]
       └→ 3. repository.legacy_search_raw(query)       [repositories/account_repository.py:38]
           └→ 4. db.execute_raw_query(query)           [utils/database_helper.py:7]
               └→ cursor.execute(query) [SINK - DEAD CODE]
```

**Why False Positive**: Function is never registered as a route and never called anywhere.

---

### VULN 7: SSTI - FALSE_POSITIVE (Sanitized) ✅ HTML Escaping
**Location**: POST /api/reports/generate

**Attack Path (4 functions)**:
```
[@login_required]  - Authentication required

1. generate_report()                            [controllers/report_controller.py:10]
   └→ 2. report_service.generate_safe_report(data)    [services/report_service.py:6]
       └→ 3. html.escape(data)  [SANITIZER]
           └→ 4. render_template_string(template)      [services/report_service.py:8]
               [SINK - SAFE]
```

**Why False Positive**: HTML escaping applied BEFORE template rendering.
**Subcategory**: 2A - Direct Sanitization

---

### VULN 8: SSTI - MUST_FIX ✅ True Positive
**Location**: POST /api/reports/custom

**Attack Path (3 functions)**:
```
1. generate_custom_report()                     [controllers/report_controller.py:17]
   └→ 2. report_service.generate_custom_report(template)  [services/report_service.py:12]
       └→ 3. render_template_string(user_template)         [services/report_service.py:13]
           [SINK - VULNERABLE]
```

**Why Must Fix**: Direct SSTI, no sanitization, no protection.

---

## Summary

| Vuln | Type | Classification | Subcategory | Path Length | Live Paths | Dead Paths |
|------|------|----------------|-------------|-------------|------------|------------|
| 1 | SQL | must_fix | - | 5 | 1 | 0 |
| 2 | SQL | false_positive_sanitized | 2A | 5 | 1 | 0 |
| 3 | SQL | false_positive_sanitized | 2B | 5 | 1 | 0 |
| 4 | SQL | false_positive_protected | 3B | 4 | 1 | 0 |
| 5 | SQL | must_fix | Mixed | 4 | 1 | 1 |
| 6 | SQL | false_positive_dead_code | - | 4 | 0 | 1 |
| 7 | SSTI | false_positive_sanitized | 2A | 4 | 1 | 0 |
| 8 | SSTI | must_fix | - | 3 | 1 | 0 |

**Total**: 3 must_fix, 5 false_positives (3 sanitized, 1 protected, 1 dead code)
**Attack Path Lengths**: 3-5 functions (comprehensive cross-file analysis required)

## File Structure

```
python_banking/
├── app.py                           # Flask app
├── controllers/
│   ├── account_controller.py        # VULN 1-6 entry points
│   └── report_controller.py         # VULN 7-8 entry points
├── services/
│   ├── account_service.py           # Business logic
│   ├── validation_service.py        # Input validation
│   └── report_service.py            # Report generation
├── repositories/
│   └── account_repository.py        # Data access
└── utils/
    ├── database_helper.py           # SINKS: cursor.execute()
    ├── input_processor.py           # Input processing
    └── auth_decorators.py           # Security controls
```

## Testing
Run AI-SAST analyzer and verify:
- All 8 vulnerabilities detected
- Correct classifications (3 must_fix, 5 false_positive)
- Proper subcategories identified
- VULN 5 correctly classified as must_fix (not dead code)
- High confidence scores (0.85+)
# testing-python-comprehensive
