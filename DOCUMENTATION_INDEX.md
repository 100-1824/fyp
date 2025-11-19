# DIDS Dashboard - Documentation Index

This directory contains comprehensive documentation about the navigation/sidebar components and routing configuration of the DIDS Dashboard application.

## Documents Overview

### 1. NAVIGATION_ROUTING_ANALYSIS.md (15 KB)
**Comprehensive Technical Analysis**

Complete reference covering all aspects of the application:
- Sidebar navigation component structure
- Complete routing configuration (4 blueprints)
- Menu items status (implemented vs unimplemented)
- Backend services architecture
- Active state logic and JavaScript
- Data flow examples (Dashboard, AI Detection)
- Template structure and HTML organization
- Implementation checklist for missing modules
- Authentication & authorization system
- Key files summary table

**Best for**: Understanding the full architecture and how components interact

---

### 2. ROUTING_DIAGRAM.txt (21 KB)
**Visual Architecture Diagrams**

ASCII visual representations of:
- Flask application factory structure
- Blueprint registration flow
- Page routing flows (Dashboard, AI Detection, Admin)
- Implemented vs unimplemented modules status
- Template dependencies and assets
- Authentication flow (5-step process)
- Service architecture diagram
- Responsive design breakpoints

**Best for**: Quick visual understanding of the overall structure

---

### 3. SIDEBAR_MENU_REFERENCE.md (11 KB)
**Developer Quick Reference Guide**

Practical implementation guide including:
- Complete sidebar menu HTML code
- Menu items table (with status, routes, templates)
- CSS class structure for styling
- Step-by-step implementation instructions
- How to implement missing modules (5 steps)
- Active state logic explanation
- Available API endpoints table
- Color scheme and variables
- Responsive behavior documentation
- Font Awesome icons reference
- Implementation checklist

**Best for**: Actually implementing new pages or modifying the sidebar

---

### 4. FILES_SUMMARY.md (11 KB)
**File Structure Reference**

Detailed file listing and organization:
- Quick file lookup tables
- Directory tree structure
- Key code locations by feature
- Backend services summary
- Implementation status (5 implemented, 4 unimplemented)
- Configuration reference
- External dependencies
- Running the application instructions

**Best for**: Finding specific files and understanding organization

---

## Quick Navigation by Use Case

### "I want to understand the overall architecture"
→ Start with **ROUTING_DIAGRAM.txt** (visual overview)
→ Then read **NAVIGATION_ROUTING_ANALYSIS.md** (detailed explanation)

### "I need to implement a new menu item"
→ Use **SIDEBAR_MENU_REFERENCE.md** (step-by-step guide)
→ Reference **FILES_SUMMARY.md** (for file locations)

### "Where is specific functionality located?"
→ Check **FILES_SUMMARY.md** (file lookup tables)
→ Use grep to search in the templates/routes directories

### "I need to understand how routing works"
→ Read **NAVIGATION_ROUTING_ANALYSIS.md** Section 2-3
→ Reference **ROUTING_DIAGRAM.txt** (Application Factory diagram)

### "What API endpoints are available?"
→ Check **SIDEBAR_MENU_REFERENCE.md** (API Endpoints Table)
→ See **NAVIGATION_ROUTING_ANALYSIS.md** Section 2.4 (Complete API listing)

### "How do I add authentication/authorization?"
→ Read **NAVIGATION_ROUTING_ANALYSIS.md** Section 9
→ Reference **ROUTING_DIAGRAM.txt** (Authentication Flow section)

---

## Key Facts at a Glance

### Frontend Structure
- **Main Templates**: 7 HTML files (index, ai_detection, admin, auth pages)
- **Routes**: 4 Flask blueprints (main, auth, api, admin)
- **Sidebar Width**: 260px (responsive, collapses on mobile)
- **Active State**: CSS class-based (hardcoded per page)

### Sidebar Menu Items
| Item | Status | Route | Template |
|------|--------|-------|----------|
| Dashboard | ✅ LIVE | `/` | `index.html` |
| AI Detection | ✅ LIVE | `/ai-detection` | `ai_detection.html` |
| Network Traffic | ❌ PLACEHOLDER | None | None |
| Threats | ❌ PLACEHOLDER | None | None |
| Analytics | ❌ PLACEHOLDER | None | None |
| User Management | ✅ LIVE (Admin) | `/admin` | `admin.html` |
| Change Password | ✅ LIVE | `/change-password` | `change_password.html` |
| Settings | ❌ PLACEHOLDER | None | None |

### Backend Services
- **PacketCaptureService**: Network traffic capture
- **ThreatDetectionService**: Signature-based detection
- **AIDetectionService**: AI-powered threat detection
- **UserService**: User management and authentication

### API Endpoints
- **15 total endpoints** under `/api` prefix
- All require `@login_required`
- Support real-time polling from frontend
- Return JSON data for charts, tables, statistics

### Real-Time Updates
- Traffic: Updates every 1 second
- Statistics: Updates every 2 seconds
- Threats: Updates every 3 seconds

---

## Implementation Status Summary

### Fully Implemented (5 modules)
1. Dashboard (`/`) - Live traffic, stats, threats monitoring
2. AI Detection (`/ai-detection`) - AI model status and detections
3. User Management (`/admin`) - Admin-only user management
4. Change Password (`/change-password`) - Password change form
5. Authentication - Login, register, logout, forgot password

### Need Implementation (4 modules)
1. Network Traffic - Currently placeholder (`#`)
2. Threats - Currently placeholder (`#`)
3. Analytics - Currently placeholder (`#`)
4. Settings - Currently placeholder (`#`)

**Note**: Backend API endpoints for these modules already exist:
- `/api/traffic`, `/api/stats`, `/api/network-health`
- `/api/threats`, `/api/combined-threats`, `/api/threat-stats`
- `/api/detection-overview`

Only frontend pages and routing need to be created.

---

## Common Development Tasks

### Add a new menu item
1. Create Flask route in `routes/main.py`
2. Create HTML template (copy from `index.html`)
3. Update sidebar href in ALL templates
4. Mark new page as `.active`
5. Add JavaScript for data fetching

See **SIDEBAR_MENU_REFERENCE.md** Section "How to Implement Missing Modules" for detailed steps.

### Modify the sidebar
1. Edit the `<nav class="nav-menu">` section
2. Change in `templates/index.html` (Lines 543-578)
3. Update `templates/ai_detection.html` to match
4. Update any other dashboard templates

### Add an API endpoint
1. Add route in `routes/api.py`
2. Use `@login_required` decorator
3. Return JSON response
4. Call from JavaScript with `fetch()`

### Configure authentication
1. Check `routes/auth.py` for implementation
2. See `app.py` lines 63-71 for user loader
3. Use `@admin_required` for admin routes
4. Use Jinja2 `{% if current_user.role == 'admin' %}` for conditional display

---

## File Organization

```
dids-dashboard/
├── routes/              # Route handlers (Flask blueprints)
├── templates/           # HTML templates with sidebar
├── services/            # Business logic (services)
├── static/              # CSS and static assets
├── utils/               # Decorators and validators
├── model/               # AI model files
├── app.py               # Flask app factory
├── config.py            # Configuration
└── requirements.txt     # Python dependencies
```

See **FILES_SUMMARY.md** for complete file listing.

---

## Key Concepts

### Active State
- The `.active` CSS class is added to the current menu item in each template
- When on Dashboard, Dashboard menu item has class `nav-item active`
- When on AI Detection, AI Detection menu item has class `nav-item active`
- No dynamic JavaScript state management needed

### Responsive Design
- Desktop (>768px): Sidebar always visible, toggle to collapse
- Mobile (≤768px): Sidebar hidden by default, toggle opens overlay
- Single JavaScript function `toggleSidebar()` handles both

### Real-Time Updates
- Dashboard polls API endpoints every 1-3 seconds
- Uses `setInterval()` with `fetch()` API
- Updates DOM elements with returned JSON data
- Chart.js used for visualizations

### Role-Based Access
- Regular Users: Dashboard, AI Detection, Change Password
- Admin Users: All above + User Management
- Decorators: `@login_required`, `@admin_required`
- Jinja2: `{% if current_user.role == 'admin' %}`

---

## Related Files in Repository

These documentation files are located in `/home/user/fyp/`:
- `NAVIGATION_ROUTING_ANALYSIS.md` - Main analysis document
- `ROUTING_DIAGRAM.txt` - Visual diagrams
- `SIDEBAR_MENU_REFERENCE.md` - Quick reference
- `FILES_SUMMARY.md` - File structure
- `DOCUMENTATION_INDEX.md` - This file

---

## How to Use This Documentation

1. **First Time Reading**: Start with ROUTING_DIAGRAM.txt for visual overview
2. **Learning the Code**: Read NAVIGATION_ROUTING_ANALYSIS.md systematically
3. **Making Changes**: Use SIDEBAR_MENU_REFERENCE.md and FILES_SUMMARY.md
4. **Finding Things**: Search by filename in FILES_SUMMARY.md

Each document has cross-references to others for related information.

---

## Questions Answered by Each Document

### NAVIGATION_ROUTING_ANALYSIS.md
- How does the sidebar component work?
- What routes are defined and where?
- What are the menu items and their status?
- How do the services work?
- What's the data flow from sidebar clicks to page updates?
- What templates are available?

### ROUTING_DIAGRAM.txt
- What's the overall architecture?
- How do Flask blueprints work together?
- What's the page routing flow?
- What's the authentication flow?
- How is the service architecture organized?

### SIDEBAR_MENU_REFERENCE.md
- What's the exact HTML for the sidebar?
- How do I implement a new menu item?
- What CSS classes affect the sidebar?
- What API endpoints can I use?
- What's the color scheme?

### FILES_SUMMARY.md
- Where is a specific file?
- What's the directory structure?
- What files do I need to modify?
- How are services organized?
- What's implemented and what's not?

---

## Next Steps

1. **Review the architecture**: Read ROUTING_DIAGRAM.txt
2. **Understand the details**: Study NAVIGATION_ROUTING_ANALYSIS.md
3. **Plan your changes**: Reference SIDEBAR_MENU_REFERENCE.md
4. **Find the files**: Use FILES_SUMMARY.md
5. **Make the changes**: Follow implementation checklists
6. **Test thoroughly**: Verify on desktop and mobile

---

Generated: November 19, 2025
Last Updated: When changes to navigation/routing are made

For questions about specific code, see the relevant source files in `routes/`, `templates/`, and `services/` directories.

