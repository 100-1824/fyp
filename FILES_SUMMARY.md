# DIDS Dashboard - Key Files Summary

## Quick File Lookup

### Frontend - Routes & Configuration
| File Path | Purpose | Lines | Status |
|-----------|---------|-------|--------|
| `routes/main.py` | Main page routing (Dashboard, AI Detection, Admin) | 31 | Active |
| `routes/auth.py` | Authentication routing (Login, Register, etc.) | 196 | Active |
| `routes/api.py` | API endpoints for frontend data | 220 | Active |
| `routes/admin.py` | Admin user management routes | 68 | Active |
| `routes/__init__.py` | Routes blueprint initialization | - | Active |

### Frontend - Templates
| File Path | Size | Purpose | Components |
|-----------|------|---------|------------|
| `templates/index.html` | 28,331 B | Dashboard | Sidebar, Stats, Traffic table, Threats, Charts |
| `templates/ai_detection.html` | 34,619 B | AI Detection | Sidebar, AI Stats, Detections, Model info |
| `templates/admin.html` | 5,236 B | Admin Dashboard | User management table, Statistics |
| `templates/login.html` | 7,918 B | Login page | Login form, Link to register |
| `templates/registration.html` | 7,381 B | Registration | Registration form, Password validation |
| `templates/change_password.html` | 7,870 B | Change Password | Password change form |
| `templates/forgot_password.html` | 3,630 B | Password Reset | Email form |

### Backend - Core Application
| File Path | Purpose | Key Functions |
|-----------|---------|----------------|
| `app.py` | Flask app factory | `create_app()` - Initializes all services and blueprints |
| `config.py` | Configuration settings | Database, logging, auth settings |
| `models.py` | User models | User, Admin classes for Flask-Login |

### Backend - Services
| File Path | Purpose | Key Classes/Methods |
|-----------|---------|-------------------|
| `services/packet_capture.py` | Packet capture & traffic | `PacketCaptureService.get_traffic_data()`, `get_stats()` |
| `services/threat_detection.py` | Signature-based detection | `ThreatDetectionService.get_recent_threats()` |
| `services/ai_detection.py` | AI-powered detection | `AIDetectionService.get_recent_detections()`, `get_model_info()` |
| `services/user_service.py` | User management | `UserService.create_user()`, `get_user_by_id()` |
| `services/flow_tracker.py` | Network flow tracking | Flow statistics and metrics |
| `services/__init__.py` | Service imports | Exports all service classes |

### Utilities
| File Path | Purpose |
|-----------|---------|
| `utils/decorators.py` | Custom decorators like `@admin_required` |
| `utils/validators.py` | Input validation functions |
| `static/style.css` | Additional CSS styles |

---

## File Location Tree

```
/home/user/fyp/dids-dashboard/
├── app.py                          # Flask app factory
├── config.py                       # Configuration
├── models.py                       # User models
├── run.py                          # Application entry point
├── requirements.txt                # Python dependencies
│
├── routes/                         # Route handlers
│   ├── __init__.py                # Blueprint initialization
│   ├── main.py                    # Dashboard, AI Detection, Admin routes
│   ├── auth.py                    # Authentication routes
│   ├── api.py                     # API endpoints
│   └── admin.py                   # Admin-specific routes
│
├── templates/                      # HTML templates
│   ├── index.html                 # Dashboard (28KB)
│   ├── ai_detection.html          # AI Detection (35KB)
│   ├── admin.html                 # Admin Dashboard
│   ├── login.html                 # Login page
│   ├── registration.html          # Registration page
│   ├── change_password.html       # Password change
│   └── forgot_password.html       # Password reset
│
├── services/                       # Business logic
│   ├── __init__.py                # Service exports
│   ├── packet_capture.py          # Packet capture service
│   ├── threat_detection.py        # Signature detection
│   ├── ai_detection.py            # AI-powered detection
│   ├── user_service.py            # User management
│   └── flow_tracker.py            # Flow tracking
│
├── static/                         # Static assets
│   └── style.css                  # CSS styles
│
├── utils/                          # Utilities
│   ├── decorators.py              # Custom decorators
│   └── validators.py              # Input validators
│
└── model/                          # AI model files
    ├── scaler.pkl
    ├── model.pkl
    └── feature_names.pkl
```

---

## Key Code Locations by Feature

### Sidebar Navigation
**Files**: 
- `/home/user/fyp/dids-dashboard/templates/index.html` (Lines 543-578)
- `/home/user/fyp/dids-dashboard/templates/ai_detection.html` (Lines 555-589)

**Structure**: `<nav class="nav-menu">` with menu items using Flask's `url_for()` helper

---

### Dashboard Page
**Route File**: `/home/user/fyp/dids-dashboard/routes/main.py` (Line 13)
```python
@main_bp.route('/')
@login_required
def dashboard():
    return render_template('index.html')
```

**Template**: `/home/user/fyp/dids-dashboard/templates/index.html`
**JavaScript Data Fetching**: Lines 776-879
- `updateTraffic()` - Fetches /api/traffic every 1 second
- `updateStats()` - Fetches /api/stats every 2 seconds
- `updateThreats()` - Fetches /api/combined-threats every 3 seconds

---

### AI Detection Page
**Route File**: `/home/user/fyp/dids-dashboard/routes/main.py` (Line 25)
```python
@main_bp.route('/ai-detection')
@login_required
def ai_detection():
    return render_template('ai_detection.html')
```

**Template**: `/home/user/fyp/dids-dashboard/templates/ai_detection.html`

---

### API Endpoints
**File**: `/home/user/fyp/dids-dashboard/routes/api.py`

**Prefix**: `/api` (line 5)

**Key Endpoints**:
- `/api/traffic` (line 20-24)
- `/api/stats` (line 26-46)
- `/api/threats` (line 48-52)
- `/api/combined-threats` (line 91-113)
- `/api/ai-detections` (line 60-66)
- `/api/ai-stats` (line 68-81)
- `/api/network-health` (line 132-162)
- `/api/detection-overview` (line 188-218)

---

### Authentication System
**Login Route**: `/home/user/fyp/dids-dashboard/routes/auth.py` (line 12)
**User Login**: Lines 36-44
**Admin Login**: Lines 25-33
**Registration**: Line 54-123
**Change Password**: Line 132-183

---

### Admin Dashboard
**Route**: `/home/user/fyp/dids-dashboard/routes/main.py` (line 18)
```python
@main_bp.route('/admin')
@admin_required
def admin_dashboard():
    return render_template('admin.html', users=users, stats=user_stats)
```

**Admin Routes**: `/home/user/fyp/dids-dashboard/routes/admin.py`
- Delete user (line 12-25)
- Toggle user status (line 27-41)
- Edit user (line 43-66)

---

### Services Integration
**Initialization**: `/home/user/fyp/dids-dashboard/app.py` (lines 73-115)

**Service Storage**: 
```python
app.packet_service = packet_service
app.threat_service = threat_service
app.ai_service = ai_service
app.user_service = user_service
```

**Services Used by Routes**:
- `app.packet_service` - Used in `/api/traffic`, `/api/stats`
- `app.threat_service` - Used in `/api/threats`, `/api/combined-threats`
- `app.ai_service` - Used in `/api/ai-detections`, `/api/ai-stats`
- `app.user_service` - Used in auth and admin routes

---

## Implementation Status

### Implemented Modules (With Routes & Templates)
1. **Dashboard** - `/` → `index.html`
2. **AI Detection** - `/ai-detection` → `ai_detection.html`
3. **User Management** - `/admin` → `admin.html` (Admin only)
4. **Change Password** - `/change-password` → `change_password.html`
5. **Authentication** - `/login`, `/register`, `/logout`, `/forgot-password`

### Unimplemented Modules (Placeholder Menu Items)
1. **Network Traffic** - Sidebar item points to `#`
2. **Threats** - Sidebar item points to `#`
3. **Analytics** - Sidebar item points to `#`
4. **Settings** - Sidebar item points to `#`

---

## Documentation Files Generated

1. **NAVIGATION_ROUTING_ANALYSIS.md** - Comprehensive guide (10 sections)
   - Sidebar component structure
   - Complete routing configuration
   - Menu items status
   - Service architecture
   - Data flow diagrams
   - Template structure
   - Implementation checklist

2. **ROUTING_DIAGRAM.txt** - Visual ASCII diagrams
   - Application factory structure
   - Page routing flows
   - Service architecture
   - Authentication flow
   - Responsive design notes

3. **SIDEBAR_MENU_REFERENCE.md** - Quick reference guide
   - Menu items table
   - CSS classes
   - How to implement missing modules
   - Active state logic
   - API endpoints
   - Color scheme
   - Implementation checklist

4. **FILES_SUMMARY.md** (this file) - File structure overview
   - Quick file lookup tables
   - Directory tree
   - Key code locations
   - Implementation status

---

## Quick Start for Development

### To Add Network Traffic Page:
1. Create route in `routes/main.py`:
   ```python
   @main_bp.route('/network-traffic')
   @login_required
   def network_traffic():
       return render_template('network_traffic.html')
   ```

2. Create `templates/network_traffic.html` (copy from `index.html`)

3. Update sidebar href in ALL templates from `#` to `{{ url_for('main.network_traffic') }}`

4. Mark Network Traffic item as `.active` in `network_traffic.html`

5. Add JavaScript to fetch `/api/traffic` and `/api/stats` data

---

## External Dependencies

### Frontend (CDN)
- Font Awesome 6.4.0 (Icons)
- Chart.js 3.9.1 (Charts)
- Google Fonts Inter (Font)

### Backend (Python)
See `requirements.txt` for complete list:
- Flask
- Flask-Login
- Flask-PyMongo
- Flask-Bcrypt
- Scapy (Packet capture)
- scikit-learn (AI model)

---

## Configuration

**File**: `config.py`

Key settings:
- `MONGO_URI` - Database connection
- `LOG_LEVEL` - Logging configuration
- `ADMIN_USERNAME` - Default admin user
- `ADMIN_DEFAULT_PASSWORD` - Default admin password
- `LOGIN_VIEW` - Redirect on login required

---

## Running the Application

```bash
# Install dependencies
pip install -r requirements.txt

# Run the application
python run.py

# Access at http://localhost:8000
```

---

## Notes

- **Active State**: Hardcoded `.active` class in each template per page
- **Sidebar Width**: 260px (CSS variable)
- **Responsive Breakpoint**: 768px
- **Real-time Updates**: JavaScript polling at 1-3 second intervals
- **Admin Access**: Controlled by `@admin_required` decorator and Jinja2 `{% if %}`
- **API Prefix**: All API routes prefixed with `/api`

---

For detailed information, see:
- `NAVIGATION_ROUTING_ANALYSIS.md` - Complete analysis
- `ROUTING_DIAGRAM.txt` - Visual diagrams
- `SIDEBAR_MENU_REFERENCE.md` - Implementation guide

