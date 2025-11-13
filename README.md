# Python Banking - AI-SAST Testing Codebase

## Purpose
Testing codebase designed to validate the AI-SAST scanner's false positive detection capabilities.

## Vulnerability Distribution (8 Total Sinks)

### 🔴 TRUE POSITIVES (2)
1. **VULN 1** - SQL Injection (must_fix): `/api/search` - No protection
2. **VULN 4** - Template Injection (good_to_fix): `/api/render/custom` - Weak validation

### 🟢 FALSE POSITIVES (6)

#### Sanitized (2)
3. **VULN 2** - SQL Injection (2B - Validation): `/api/user/profile` - `re.fullmatch(r'^[0-9]+$')`
4. **VULN 3** - SQL Injection (2C - Architectural): `/api/report/generate` - ORM QueryBuilder

#### Protected (3)
5. **VULN 5** - Template Injection (3A - Auth): `/api/user/preferences` - `@login_required`
6. **VULN 6** - SQL Injection (3A - Auth/Authz): `/api/admin/audit` - `@admin_required`
7. **VULN 7** - Template Injection (3B - Defense-in-Depth): `/api/admin/template/preview` - 5 layers

#### Mixed Scenario (1)
8. **VULN 8** - SQL Injection (Mixed Paths): `/api/legacy/import`
   - Path 1: Dead code (legacy_mode_enabled = False)
   - Path 2: Live + Sanitized (alphanumeric validation)
   - Path 3: Dead code (admin_legacy_mode = False)

## Testing Coverage

✅ All 3 FP categories (sanitized, protected, mixed/dead)  
✅ Subcategories: 2B (Validation), 2C (Architectural), 3A (Auth), 3B (Defense-in-Depth)  
✅ Weak vs strong validation scenarios  
✅ Multi-hop attack paths (2-4 hops)  
✅ Mixed path scenarios (multiple paths with different viability)  
✅ Dead code with conditional branches  

## Key Test Scenarios

### Subcategory 2B - Validation-Based (VULN 2)
- Tests: `re.fullmatch()` with strict pattern `^[0-9]+$`
- Challenge: Verify validation is effective (not weak like `re.match()`)
- Expected: `false_positive_sanitized` with high confidence

### Subcategory 2C - Architectural (VULN 3) ⭐ NEW
- Tests: ORM query builder pattern (like SQLAlchemy)
- Challenge: Recognize framework architectural protection
- Expected: `false_positive_sanitized` with reference to ORM pattern

### Mixed Scenario (VULN 8) ⭐ ENHANCED
- Tests: Multiple paths with different classifications
- Challenge: Classify each path independently, assess overall vulnerability
- Expected: Per-path classification + overall `false_positive` (all live paths protected)

## Running Tests

```bash
cd python_banking
python app.py
```

Test endpoints:
```bash
# VULN 1 - Should detect as must_fix
curl "http://localhost:5000/api/search?query=test"

# VULN 2 - Should detect as FP (validation)
curl "http://localhost:5000/api/user/profile?user_id=123"

# VULN 3 - Should detect as FP (architectural)
curl -X POST http://localhost:5000/api/report/generate -H "Content-Type: application/json" -d '{"report_type":"payment","user_filter":"1"}'

# VULN 8 - Should detect as FP (mixed scenario, live path sanitized)
curl -X POST http://localhost:5000/api/legacy/import -H "Content-Type: application/json" -d '{"data":"test123","is_admin":false,"type":"standard"}'
```

## Expected AI-SAST Analysis

### Static Analysis Engine Should:
- ✅ Build complete call graphs across all services
- ✅ Detect 8 entry points (@app.route decorators)
- ✅ Resolve cross-file imports correctly
- ✅ Identify dead branches (legacy_mode_enabled, admin_legacy_mode)
- ✅ Track parameter flow through validators
- ✅ Generate multiple paths for VULN 8 (3 paths total)

### LLM Processor Should:
- ✅ Cite specific code evidence (file paths + line numbers)
- ✅ Recognize `re.fullmatch()` as strict validation
- ✅ Recognize QueryBuilder as architectural protection
- ✅ Distinguish weak vs strong validation (VULN 4 vs VULN 2)
- ✅ Assess defense-in-depth (5+ layers in VULN 7)
- ✅ Handle mixed paths correctly (classify per-path, overall assessment)
- ✅ Use professional language (no internal IDs like snippet_id)

## Validation Checklist

- [ ] VULN 1: `must_fix` (high confidence 0.9+)
- [ ] VULN 2: `false_positive_sanitized` (Subcategory 2B, cite fullmatch)
- [ ] VULN 3: `false_positive_sanitized` (Subcategory 2C, cite ORM/QueryBuilder)
- [ ] VULN 4: `good_to_fix` (medium confidence 0.7-0.8, explain weak validation)
- [ ] VULN 5: `false_positive_protected` (Subcategory 3A, cite @login_required)
- [ ] VULN 6: `false_positive_protected` (Subcategory 3A, cite @admin_required)
- [ ] VULN 7: `false_positive_protected` (Subcategory 3B, list 5 layers)
- [ ] VULN 8: Mixed scenario handled correctly:
  - [ ] Path 1: `DEAD_CODE` (legacy_mode_enabled)
  - [ ] Path 2: `SECURE`/`PROTECTED` (validated input)
  - [ ] Path 3: `DEAD_CODE` (admin_legacy_mode)
  - [ ] Overall: `false_positive` (no exploitable live paths)
