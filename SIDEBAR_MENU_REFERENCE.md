# Sidebar Menu Configuration - Quick Reference

## Sidebar Menu Items Definition

**File**: `/home/user/fyp/dids-dashboard/templates/index.html` (Lines 543-578)
**Also Used In**: `ai_detection.html` and other dashboard templates

### Menu Structure HTML

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

## Menu Items Table

| Order | Icon | Label | href | Route | Template | Status | Auth | Role |
|-------|------|-------|------|-------|----------|--------|------|------|
| 1 | fa-home | Dashboard | `{{ url_for('main.dashboard') }}` | `/` | `index.html` | ✅ LIVE | Required | User/Admin |
| 2 | fa-brain | AI Detection | `{{ url_for('main.ai_detection') }}` | `/ai-detection` | `ai_detection.html` | ✅ LIVE | Required | User/Admin |
| 3 | fa-network-wired | Network Traffic | `#` | None | None | ❌ PLACEHOLDER | Required | User/Admin |
| 4 | fa-shield-virus | Threats | `#` | None | None | ❌ PLACEHOLDER | Required | User/Admin |
| 5 | fa-chart-line | Analytics | `#` | None | None | ❌ PLACEHOLDER | Required | User/Admin |
| 6* | fa-users-cog | User Management | `{{ url_for('main.admin_dashboard') }}` | `/admin` | `admin.html` | ✅ LIVE | Required | Admin Only |
| 7 | fa-key | Change Password | `{{ url_for('auth.change_password') }}` | `/change-password` | `change_password.html` | ✅ LIVE | Required | User/Admin |
| 8 | fa-cog | Settings | `#` | None | None | ❌ PLACEHOLDER | Required | User/Admin |

*Item 6 (User Management) is only visible to admin users due to `{% if current_user.role == 'admin' %}` condition

## CSS Class Structure

### Active State Indicator
```css
.nav-item.active {
    background: var(--bg-light);      /* Light blue background */
    color: var(--primary);             /* Blue text */
    border-right: 3px solid var(--primary); /* Blue right border */
}
```

### Hover State
```css
.nav-item:hover {
    background: var(--bg-light);       /* Light background on hover */
    color: var(--text-dark);           /* Dark text on hover */
}
```

## How to Implement Missing Modules

### Step 1: Create Flask Route
**File**: `/home/user/fyp/dids-dashboard/routes/main.py`

```python
@main_bp.route('/network-traffic')
@login_required
def network_traffic():
    """Network Traffic analysis page"""
    return render_template('network_traffic.html')
```

### Step 2: Create HTML Template
**File**: `/home/user/fyp/dids-dashboard/templates/network_traffic.html`

Copy structure from `index.html` or `ai_detection.html`:
- Include sidebar
- Update active class (mark Network Traffic as `.active`)
- Add module-specific content

### Step 3: Update Sidebar Menu
**File**: `/home/user/fyp/dids-dashboard/templates/index.html` (Lines 552-555)

Change from:
```html
<a href="#" class="nav-item">
    <i class="fas fa-network-wired"></i>
    <span>Network Traffic</span>
</a>
```

To:
```html
<a href="{{ url_for('main.network_traffic') }}" class="nav-item">
    <i class="fas fa-network-wired"></i>
    <span>Network Traffic</span>
</a>
```

### Step 4: Update All Template Files
Repeat Step 3 in:
- `ai_detection.html`
- `admin.html` (if applicable)
- Any other dashboard templates

### Step 5: Add JavaScript (Optional)
If the page needs real-time data, add JavaScript to fetch from API endpoints:

```javascript
async function updateNetworkTraffic() {
    try {
        const data = await fetch('/api/traffic').then(r => r.json());
        // Update DOM with data
    } catch(e) { 
        console.error(e); 
    }
}

// Call on page load
updateNetworkTraffic();
// Or set interval for real-time updates
setInterval(updateNetworkTraffic, 1000);
```

## Active State Logic

### How Current Page is Marked as Active

1. **HTML Level**: The `.active` class is hardcoded in each template
   ```html
   <!-- In index.html -->
   <a href="{{ url_for('main.dashboard') }}" class="nav-item active">
       <i class="fas fa-home"></i>
       <span>Dashboard</span>
   </a>
   
   <!-- In ai_detection.html -->
   <a href="{{ url_for('main.ai_detection') }}" class="nav-item active">
       <i class="fas fa-brain"></i>
       <span>AI Detection</span>
   </a>
   ```

2. **CSS Level**: Active class applies styling
   ```css
   .nav-item.active {
       background: var(--bg-light);
       color: var(--primary);
       border-right: 3px solid var(--primary);
   }
   ```

3. **JavaScript Level**: Sidebar toggle functionality
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

## API Endpoints Available for Use

| Endpoint | Purpose | Example Response |
|----------|---------|------------------|
| `/api/traffic` | Network traffic data | `[{timestamp, source, destination, protocol, size, threat}]` |
| `/api/stats` | Network statistics | `{total_packets, pps, threats_blocked, protocols: {}, top_talkers: {}}` |
| `/api/threats` | Signature-based threats | `[{timestamp, source, destination, signature, severity, action}]` |
| `/api/ai-detections` | AI-based detections | `[{timestamp, source, destination, attack_type, confidence, action}]` |
| `/api/combined-threats` | Signature + AI threats | `[{...threat, detection_method: 'signature' or 'ai'}]` |
| `/api/threat-stats` | Threat statistics | `{total_threats, blocked_count, by_severity: {}}` |
| `/api/ai-stats` | AI detection statistics | `{total_detections, by_attack_type: {}, average_confidence: float}` |
| `/api/network-health` | Network health score | `{health_score: float, status: string, threats_detected: int}` |
| `/api/detection-overview` | Combined detection overview | `{signature_based: {}, ai_based: {}}` |

## Sidebar User Section

Located at bottom of sidebar (Lines 580-591 in index.html):

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

**JavaScript Population** (Lines 768-773):
```javascript
fetch('/api/current_user').then(r => r.json()).then(d => {
    if (d.name) {
        document.getElementById('current-user').textContent = d.name;
        document.getElementById('user-avatar').textContent = d.name[0].toUpperCase();
    }
});
```

## Color Scheme (CSS Variables)

All used in sidebar styling:
```css
--primary: #2563eb           /* Active item color - Blue */
--primary-dark: #1e40af      /* Darker blue */
--text-dark: #0f172a         /* Dark text */
--text-light: #64748b        /* Light gray text */
--bg-light: #f8fafc          /* Light background */
--border: #e2e8f0            /* Border color */
--success: #10b981           /* Green for success states */
--danger: #ef4444            /* Red for alerts/threats */
--warning: #f59e0b           /* Orange for warnings */
--sidebar-width: 260px       /* Sidebar width */
```

## Responsive Behavior

### Desktop (>768px)
- Sidebar always visible (260px width)
- Menu toggle button: Collapse/Expand sidebar
- Main content adjusts width based on sidebar state

### Mobile (≤768px)
- Sidebar hidden by default (translateX off-screen)
- Menu toggle button: Opens sidebar as overlay
- Sidebar can be closed by clicking menu toggle or content
- Main content: Full width

**Toggle Implementation**:
```javascript
if (window.innerWidth <= 768) {
    sidebar.classList.toggle('mobile-open');  // Show/hide overlay
} else {
    sidebar.classList.toggle('collapsed');    // Collapse/expand
    mainContent.classList.toggle('expanded');
}
```

## Navigation Icons (Font Awesome 6.4.0)

Used in sidebar menu items:
- `fa-home` - Dashboard
- `fa-brain` - AI Detection
- `fa-network-wired` - Network Traffic
- `fa-shield-virus` - Threats
- `fa-chart-line` - Analytics
- `fa-users-cog` - User Management
- `fa-key` - Change Password
- `fa-cog` - Settings
- `fa-times` - Close button
- `fa-bars` - Menu toggle
- `fa-sign-out-alt` - Logout

## Page Title Updates

Top bar page title is set in each template:
```html
<h1 class="page-title">Network Security Dashboard</h1> <!-- Dashboard -->
<h1 class="page-title">AI Detection</h1>               <!-- AI Detection -->
```

**No dynamic JavaScript page title update** - Title is hardcoded per page template.

## Conditional Rendering for Admin

```html
{% if current_user.role == 'admin' %}
    <a href="{{ url_for('main.admin_dashboard') }}" class="nav-item">
        <i class="fas fa-users-cog"></i>
        <span>User Management</span>
    </a>
{% endif %}
```

- Admin role: User Management appears
- Regular user role: User Management hidden

## Implementation Checklist

For each missing module (Network Traffic, Threats, Analytics, Settings):

- [ ] Create Flask route in `routes/main.py`
- [ ] Create HTML template file (copy from `index.html` as base)
- [ ] Update all template sidebar `href` from `#` to route
- [ ] Mark current page `.nav-item` with `.active` class
- [ ] Update page title in `.page-title`
- [ ] Add module-specific content HTML
- [ ] Add JavaScript for API calls (if real-time data needed)
- [ ] Add CSS for module-specific styling
- [ ] Test on desktop and mobile
- [ ] Verify active state highlighting works

