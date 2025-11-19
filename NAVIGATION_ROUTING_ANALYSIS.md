# DIDS Dashboard - Navigation/Sidebar & Routing Configuration Analysis

## Overview
The DIDS (Distributed Intrusion Detection System) Dashboard is a Flask-based web application with a responsive sidebar navigation system. The application uses Flask Blueprints for modular routing.

---

## 1. SIDEBAR NAVIGATION COMPONENT

### Location
- **Primary Files**: `/home/user/fyp/dids-dashboard/templates/`
  - `index.html` (Dashboard page)
  - `ai_detection.html` (AI Detection page)
  - Both share the same sidebar HTML structure

### Sidebar HTML Structure (Lines 543-578 in index.html)
```html
<nav class="nav-menu">
    <a href="{{ url_for('main.dashboard') }}" class="nav-item active">
        <i class="fas fa-home"></i>
        <span>Dashboard</span>
    </a>
    <a href="{{ url_for('main.ai_detection') }}" class="nav-item">
        <i class="fas fa-brain"></i>
        <span>AI Detection</span>
    </a>
    <a href="#" class="nav-item">
        <i class="fas fa-network-wired"></i>
        <span>Network Traffic</span>
    </a>
    <a href="#" class="nav-item">
        <i class="fas fa-shield-virus"></i>
        <span>Threats</span>
    </a>
    <a href="#" class="nav-item">
        <i class="fas fa-chart-line"></i>
        <span>Analytics</span>
    </a>
    {% if current_user.role == 'admin' %}
    <a href="{{ url_for('main.admin_dashboard') }}" class="nav-item">
        <i class="fas fa-users-cog"></i>
        <span>User Management</span>
    </a>
    {% endif %}
    <a href="{{ url_for('auth.change_password') }}" class="nav-item">
        <i class="fas fa-key"></i>
        <span>Change Password</span>
    </a>
    <a href="#" class="nav-item">
        <i class="fas fa-cog"></i>
        <span>Settings</span>
    </a>
</nav>
```

### Sidebar Styling (CSS)
- **Width**: 260px (CSS variable `--sidebar-width`)
- **Position**: Fixed, left side, full height
- **Colors**: 
  - Background: White
  - Active Item: Light blue background with 3px right border
  - Hover: Light background with darker text
- **Responsive**: Collapses on mobile (≤768px)

### Active State Logic
- The `.active` class highlights current page
- Active item gets blue color and right border
- Page title updates dynamically via JavaScript

### Sidebar User Section
Located at bottom of sidebar (Lines 580-591):
```html
<div class="user-section">
    <div class="user-avatar" id="user-avatar">U</div>
    <div class="user-info">
        <div class="user-name" id="current-user">Loading...</div>
        <div class="user-role">{{ current_user.role|capitalize }}</div>
    </div>
    <a href="{{ url_for('auth.logout') }}">
        <button class="logout-btn">
            <i class="fas fa-sign-out-alt"></i>
        </button>
    </a>
</div>
```

---

## 2. ROUTING CONFIGURATION

### Application Factory & Blueprint Registration
**File**: `/home/user/fyp/dids-dashboard/app.py`

Blueprints are registered in the `create_app()` function:
```python
auth_bp = init_auth_routes(app, mongo, bcrypt, user_service)
main_bp = init_main_routes(app, mongo, user_service)
admin_bp = init_admin_routes(app, user_service)
api_bp = init_api_routes(app, packet_service, threat_service, ai_service)

app.register_blueprint(auth_bp)
app.register_blueprint(main_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(api_bp)
```

### 2.1 MAIN ROUTES (main.py)
**Location**: `/home/user/fyp/dids-dashboard/routes/main.py`

| Route | Method | Handler | Template | Auth | Role |
|-------|--------|---------|----------|------|------|
| `/` | GET | `dashboard()` | `index.html` | Required | User/Admin |
| `/admin` | GET | `admin_dashboard()` | `admin.html` | Required | Admin Only |
| `/ai-detection` | GET | `ai_detection()` | `ai_detection.html` | Required | User/Admin |

**Code Snippet**:
```python
@main_bp.route('/')
@login_required
def dashboard():
    if current_user.role == 'admin':
        return redirect(url_for('main.admin_dashboard'))
    return render_template('index.html')

@main_bp.route('/ai-detection')
@login_required
def ai_detection():
    """AI Detection dashboard page"""
    return render_template('ai_detection.html')
```

### 2.2 AUTHENTICATION ROUTES (auth.py)
**Location**: `/home/user/fyp/dids-dashboard/routes/auth.py`

| Route | Method | Handler | Template | Purpose |
|-------|--------|---------|----------|---------|
| `/login` | GET, POST | `login()` | `login.html` | User/Admin login |
| `/register` | GET, POST | `register()` | `registration.html` | User registration |
| `/logout` | GET | `logout()` | - | Logout user |
| `/change-password` | GET, POST | `change_password()` | `change_password.html` | Change password |
| `/forgot-password` | GET, POST | `forgot_password()` | `forgot_password.html` | Password reset |

### 2.3 ADMIN ROUTES (admin.py)
**Location**: `/home/user/fyp/dids-dashboard/routes/admin.py`
**Prefix**: `/admin`

| Route | Method | Handler | Purpose |
|-------|--------|---------|---------|
| `/admin/delete-user/<user_id>` | POST | `delete_user()` | Delete user |
| `/admin/toggle-user/<user_id>` | POST | `toggle_user()` | Activate/Deactivate user |
| `/admin/edit-user/<user_id>` | GET, POST | `edit_user()` | Edit user info |

All require `@admin_required` decorator.

### 2.4 API ROUTES (api.py)
**Location**: `/home/user/fyp/dids-dashboard/routes/api.py`
**Prefix**: `/api`

#### Core API Endpoints

| Endpoint | Method | Purpose | Handler |
|----------|--------|---------|---------|
| `/api/current_user` | GET | Get logged-in user info | `current_user_info()` |
| `/api/traffic` | GET | Get recent traffic data (limit: 100) | `traffic()` |
| `/api/stats` | GET | Get network statistics + PPS | `stats()` |
| `/api/threats` | GET | Get signature-based threats | `threats()` |
| `/api/threat-stats` | GET | Get threat statistics | `threat_stats()` |
| `/api/ai-detections` | GET | Get AI-based threat detections | `ai_detections()` |
| `/api/ai-stats` | GET | Get AI detection statistics | `ai_stats()` |
| `/api/ai-model-info` | GET | Get AI model information | `ai_model_info()` |
| `/api/combined-threats` | GET | Combined signature + AI threats | `combined_threats()` |
| `/api/capture/status` | GET | Get packet capture status | `capture_status()` |
| `/api/capture/toggle` | POST | Toggle packet capture on/off | `toggle_capture()` |
| `/api/network-health` | GET | Get network health metrics | `network_health()` |
| `/api/signatures` | GET | Get all threat signatures | `signatures()` |
| `/api/ai-threshold` | POST | Set AI confidence threshold | `set_ai_threshold()` |
| `/api/detection-overview` | GET | Overview of all detection methods | `detection_overview()` |

All API routes require `@login_required`.

**Key API Response Example** (Combined Threats):
```python
{
    'timestamp': '2024-11-19 10:30:45',
    'source': '192.168.1.100',
    'destination': '10.0.0.1',
    'attack_type': 'Port Scan',
    'confidence': 95.5,
    'action': 'BLOCKED',
    'detection_method': 'ai' or 'signature'
}
```

---

## 3. MENU ITEMS STATUS & COMPONENT MAPPING

### Implemented Modules
✅ **Dashboard** (`/`)
- Component: `index.html` / `/home/user/fyp/dids-dashboard/templates/index.html`
- Route: `main.dashboard`
- Features:
  - Live network traffic table
  - Statistics cards (PPS, Total Packets, Threats, Top Talker)
  - Protocol distribution chart
  - Recent threats (combined signature + AI)
  - Live capture toggle

✅ **AI Detection** (`/ai-detection`)
- Component: `ai_detection.html` / `/home/user/fyp/dids-dashboard/templates/ai_detection.html`
- Route: `main.ai_detection`
- Features:
  - AI model information and status
  - AI-based threat detections
  - Detection statistics
  - Confidence threshold configuration
  - Attack type distribution

✅ **User Management** (`/admin`) - Admin Only
- Component: `admin.html` / `/home/user/fyp/dids-dashboard/templates/admin.html`
- Route: `main.admin_dashboard`
- Features:
  - User table with edit/delete/toggle
  - User statistics
  - Admin-only access

✅ **Change Password** (`/change-password`)
- Component: `change_password.html`
- Route: `auth.change_password`
- Features:
  - Password change form
  - Validation for both admin and regular users

### Unimplemented Modules (Placeholder Status)
❌ **Network Traffic** - href="#"
- Sidebar MenuItem: Line 552-555 in index.html
- Status: Placeholder, no route or component
- Should map to: Detailed network traffic analysis, flow analysis, etc.

❌ **Threats** - href="#"
- Sidebar MenuItem: Line 556-559 in index.html
- Status: Placeholder, no route or component
- Data available via `/api/combined-threats` endpoint
- Should include: Detailed threat analysis, severity breakdown, etc.

❌ **Analytics** - href="#"
- Sidebar MenuItem: Line 560-563 in index.html
- Status: Placeholder, no route or component
- Should include: Network analytics, trends, historical analysis, etc.

❌ **Settings** - href="#"
- Sidebar MenuItem: Line 574-577 in index.html
- Status: Placeholder, no route or component
- Should include: System settings, detection thresholds, capture options, etc.

---

## 4. BACKEND SERVICES ARCHITECTURE

### Services Location
`/home/user/fyp/dids-dashboard/services/`

| Service | File | Purpose |
|---------|------|---------|
| PacketCaptureService | `packet_capture.py` | Packet capture, traffic data, flow counting |
| ThreatDetectionService | `threat_detection.py` | Signature-based threat detection |
| AIDetectionService | `ai_detection.py` | AI-powered threat detection |
| UserService | `user_service.py` | User management, authentication |
| FlowTracker | `flow_tracker.py` | Network flow tracking and statistics |

### Service Initialization (in app.py)
```python
# 1. Initialize threat detection service
threat_service = ThreatDetectionService(app.config)

# 2. Initialize AI detection service
ai_service = AIDetectionService(app.config, model_path=model_path)

# 3. Initialize packet capture service
packet_service = PacketCaptureService(app.config, threat_service, ai_service)

# 4. Initialize user service
user_service = UserService(mongo, bcrypt)

# Services stored in app context
app.packet_service = packet_service
app.threat_service = threat_service
app.ai_service = ai_service
app.user_service = user_service
```

---

## 5. ACTIVE STATE LOGIC

### JavaScript Sidebar Toggle
**Location**: Lines 732-743 in index.html
```javascript
function toggleSidebar() {
    const sidebar = document.getElementById('sidebar');
    const mainContent = document.getElementById('mainContent');
    
    if (window.innerWidth <= 768) {
        sidebar.classList.toggle('mobile-open');
    } else {
        sidebar.classList.toggle('collapsed');
        mainContent.classList.toggle('expanded');
    }
}
```

### Active Class Assignment
- Dashboard: Active on `/` (index.html line 544)
- AI Detection: Active on `/ai-detection` (ai_detection.html line 559)
- User Management: Active on `/admin` (admin.html has different layout)

---

## 6. DATA FLOW FROM SIDEBAR TO PAGES

### Example: Dashboard Navigation Flow
1. User clicks "Dashboard" in sidebar
2. Click handler routes to `{{ url_for('main.dashboard') }}` = `/`
3. Flask route handler renders `index.html`
4. JavaScript on page load calls API endpoints:
   - `/api/current_user` - Get user info
   - `/api/traffic` - Get network traffic
   - `/api/stats` - Get statistics
   - `/api/combined-threats` - Get threats
5. Chart.js and JavaScript update DOM with real-time data
6. Updates refresh every 1-3 seconds:
   - Traffic: 1 second
   - Stats: 2 seconds
   - Threats: 3 seconds

### Example: AI Detection Flow
1. User clicks "AI Detection" in sidebar
2. Route: `/ai-detection` → `main.ai_detection()`
3. Renders `ai_detection.html` with similar sidebar
4. JavaScript calls API endpoints:
   - `/api/ai-model-info` - Model status and features
   - `/api/ai-stats` - Detection statistics
   - `/api/ai-detections` - Recent detections
   - `/api/detection-overview` - Combined detection overview

---

## 7. TEMPLATE STRUCTURE (HTML Files)

All main dashboard templates share similar structure:

```
<sidebar>
    - Header with logo
    - Navigation menu (nav-menu)
    - User section at bottom
</sidebar>

<main-content>
    - Top bar with:
        - Menu toggle button
        - Page title
        - Action buttons (e.g., Live/Paused capture)
    
    - Dashboard content area:
        - Stats grid (4 columns)
        - Content grid (main content + sidebar)
        - Cards with data tables and charts
</main-content>
```

### CSS Variables (Consistent Across Templates)
```css
--primary: #2563eb
--primary-dark: #1e40af
--text-dark: #0f172a
--text-light: #64748b
--bg-light: #f8fafc
--border: #e2e8f0
--success: #10b981
--danger: #ef4444
--warning: #f59e0b
--sidebar-width: 260px
```

---

## 8. IMPLEMENTATION CHECKLIST FOR MISSING MODULES

To implement the missing modules (Network Traffic, Threats, Analytics, Settings):

### For Each Module:
- [ ] Create Flask route in appropriate blueprint (`main.py` or new blueprint)
- [ ] Create HTML template file in `/templates/`
- [ ] Add `.active` class assignment logic
- [ ] Update sidebar href from `#` to actual route
- [ ] Create API endpoints (if needed)
- [ ] Copy sidebar structure from existing templates
- [ ] Implement module-specific content/logic
- [ ] Add JavaScript for data fetching and updates
- [ ] Implement responsive CSS

---

## 9. AUTHENTICATION & AUTHORIZATION

### Decorators Used
- `@login_required` - Requires user to be logged in
- `@admin_required` - Requires admin role (custom decorator)

### Role-Based Access
- **Regular Users**: Dashboard, AI Detection, Change Password
- **Admin Users**: All above + User Management
- **Conditional Rendering**: User Management menu item only shows for admins (Jinja2 `{% if current_user.role == 'admin' %}`)

---

## 10. KEY FILES SUMMARY

| File Path | Purpose |
|-----------|---------|
| `routes/main.py` | Main page routes (dashboard, ai_detection, admin) |
| `routes/auth.py` | Authentication routes |
| `routes/api.py` | API endpoints for frontend |
| `routes/admin.py` | Admin user management routes |
| `templates/index.html` | Dashboard page with full sidebar |
| `templates/ai_detection.html` | AI Detection page with full sidebar |
| `templates/admin.html` | Admin dashboard |
| `services/packet_capture.py` | Traffic data service |
| `services/threat_detection.py` | Signature-based detection |
| `services/ai_detection.py` | AI-based detection |
| `services/user_service.py` | User management service |
| `app.py` | Application factory and service initialization |

---

## Summary

The DIDS Dashboard has a **well-structured modular architecture**:
- **2 implemented modules**: Dashboard + AI Detection
- **4 placeholder menu items**: Network Traffic, Threats, Analytics, Settings
- **Strong backend API**: 15 RESTful endpoints supporting both signature and AI detection
- **Responsive design**: Fixed sidebar with mobile collapse support
- **Real-time updates**: JavaScript polls API endpoints every 1-3 seconds
- **Role-based access**: Admin-only features properly gated

**Next Steps for Development**: 
Create the missing module pages (Network Traffic, Threats, Analytics, Settings) by following the existing pattern established by Dashboard and AI Detection pages.

