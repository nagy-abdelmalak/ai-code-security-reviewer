# Wireframes & Storyboard

## Sketches / Wireframes

### ① Landing page (unauthenticated)
- Title + short tool description
- Buttons: **Login**, **Register**

### ② Login
- Email field
- Password field
- **Login** button
- *Forgot password?* link
- *Register* link

### ③ Register
- Username field
- Email field
- Password field (with strength indicator)
- Confirm password
- **Register** button
- *Role is NOT user-selectable: new users default to Developer. Role promotions are handled by an Admin (ADR-006, NFR-S3).*

### ④ Home page (authenticated)
- Navigation bar (Home / Submit / History / Profile / Logout)
- Personal stats: total submissions, total findings, unreviewed findings
- Prominent **New Submission** button
- Last 5 submissions (compact list)

### ⑤ Submit Code
- Textarea for code paste
- **Upload file** button (`.py`, max 1 MB)
- Language dropdown (Python — only option in MVP)
- Toggle: *Run LLM analysis*
- LLM model dropdown (visible only when LLM toggle is on)
- Toggle: *Include plain-language explanations* (thesis variable)
- Disclosure note: *"LLM analysis transmits your code to the external provider."*
- **Analyze** button

### ⑥ Results (side-by-side)
- Header: submission ID, date, language
- Two columns:
  - **Left (Semgrep):** findings list with severity (color-coded), line number, rule ID, message
  - **Right (LLM):** same structure + explanation (if toggle was on)
- Per finding: current status badge + expandable review thread
- **Add review** button (visible based on role)
- Export buttons: **Download JSON**
- *Back to History* link

### ⑦ History
- Paginated list of submissions: date, language, total findings, unreviewed count
- Filters: date range, severity present, status
- Click a row → navigate to the corresponding Results view

### ⑧ Auditor Dashboard *(Auditor role only)*
- List of assigned developers
- For each: recent submissions count, unreviewed findings count
- Click → view that developer's submissions

### ⑨ Admin User Management *(Admin role only)*
- User list with email, role, status (active / disabled)
- Actions: change role, disable, enable
- **Create user** button
- Audit log viewer (filter by event type, user, date range)

---

## Storyboard

### Characters
- **Nagy** — a developer using the tool to analyze his own code
- **Sofia** — a security auditor assigned to Nagy
- **Andrea** — the system administrator

### Scenario 1 — Registration and Login (Nagy)
**Goal:** register and access the application.

- Nagy opens the app and clicks **Register**
- He enters username, email, password
- He is registered with the default role (Developer)
- He logs in and lands on the Home page

### Scenario 2 — Code submission and analysis (Nagy)
**Goal:** analyze a Python script.

- From the Home page, Nagy clicks **New Submission**
- He pastes his code into the textarea
- He enables the *LLM analysis* and *explanations* toggles
- He clicks **Analyze**
- The Results view displays Semgrep findings on the left and LLM findings on the right, side by side

### Scenario 3 — Review (Sofia, Auditor)
**Goal:** review Nagy's findings.

- From the Auditor Dashboard, Sofia sees that Nagy has 3 unreviewed findings
- She clicks on Nagy's submission to open the Results view
- For each finding she selects a status (*confirmed* / *false positive* / *accepted risk*) and optionally adds a comment
- The system updates `Finding.status` and records a `REVIEW_CREATED` event in the audit log

### Scenario 4 — User management (Andrea, Admin)
**Goal:** promote Sofia from Developer to Auditor and assign her to Nagy.

- Andrea opens **Admin User Management**
- He searches for Sofia, clicks **Change role** → Auditor
- Andrea then creates an `AuditorAssignment` linking Sofia (auditor) to Nagy (developer)

### Scenario 5 — History (Nagy)
**Goal:** revisit past submissions with filters.

- Nagy clicks **History**
- He applies filters: *severity = high* and *status = unreviewed*
- He clicks a submission to revisit its Results view
