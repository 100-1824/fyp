/**
 * Interactive Utilities for DIDS Dashboard
 * Provides notifications, animations, and UI helpers
 */

// Toast Notification System
class Toast {
    constructor() {
        this.container = this.createContainer();
    }

    createContainer() {
        let container = document.getElementById('toast-container');
        if (!container) {
            container = document.createElement('div');
            container.id = 'toast-container';
            container.style.cssText = `
                position: fixed;
                top: 20px;
                right: 20px;
                z-index: 10000;
                display: flex;
                flex-direction: column;
                gap: 10px;
            `;
            document.body.appendChild(container);
        }
        return container;
    }

    show(message, type = 'info', duration = 3000) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;

        const icons = {
            success: '✓',
            error: '✗',
            warning: '⚠',
            info: 'ℹ'
        };

        const colors = {
            success: '#10b981',
            error: '#ef4444',
            warning: '#f59e0b',
            info: '#3b82f6'
        };

        toast.style.cssText = `
            background: white;
            padding: 16px 20px;
            border-radius: 8px;
            box-shadow: 0 4px 12px rgba(0,0,0,0.15);
            border-left: 4px solid ${colors[type]};
            min-width: 300px;
            max-width: 400px;
            animation: slideIn 0.3s ease;
            display: flex;
            align-items: center;
            gap: 12px;
        `;

        toast.innerHTML = `
            <div style="width: 24px; height: 24px; background: ${colors[type]}; color: white;
                        border-radius: 50%; display: flex; align-items: center;
                        justify-content: center; font-weight: bold; flex-shrink: 0;">
                ${icons[type]}
            </div>
            <div style="flex: 1; font-size: 14px; color: #334155;">${message}</div>
            <button onclick="this.parentElement.remove()"
                    style="background: none; border: none; color: #94a3b8;
                           cursor: pointer; font-size: 18px; padding: 0; width: 20px;">×</button>
        `;

        this.container.appendChild(toast);

        if (duration > 0) {
            setTimeout(() => {
                toast.style.animation = 'slideOut 0.3s ease';
                setTimeout(() => toast.remove(), 300);
            }, duration);
        }

        return toast;
    }

    success(message, duration) {
        return this.show(message, 'success', duration);
    }

    error(message, duration) {
        return this.show(message, 'error', duration);
    }

    warning(message, duration) {
        return this.show(message, 'warning', duration);
    }

    info(message, duration) {
        return this.show(message, 'info', duration);
    }
}

// Loading Overlay
class LoadingOverlay {
    constructor() {
        this.overlay = null;
    }

    show(message = 'Loading...') {
        if (this.overlay) return;

        this.overlay = document.createElement('div');
        this.overlay.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 9999;
            display: flex;
            align-items: center;
            justify-content: center;
            backdrop-filter: blur(4px);
        `;

        this.overlay.innerHTML = `
            <div style="background: white; padding: 30px 40px; border-radius: 12px;
                        box-shadow: 0 8px 32px rgba(0,0,0,0.3); text-align: center;">
                <div style="width: 50px; height: 50px; border: 4px solid #e5e7eb;
                            border-top-color: #3b82f6; border-radius: 50%;
                            margin: 0 auto 16px; animation: spin 0.8s linear infinite;"></div>
                <div style="font-size: 16px; font-weight: 500; color: #334155;">${message}</div>
            </div>
        `;

        document.body.appendChild(this.overlay);
    }

    hide() {
        if (this.overlay) {
            this.overlay.remove();
            this.overlay = null;
        }
    }
}

// Modal Dialog
class Modal {
    constructor() {
        this.modal = null;
    }

    show(title, content, options = {}) {
        this.hide(); // Close any existing modal

        this.modal = document.createElement('div');
        this.modal.style.cssText = `
            position: fixed;
            top: 0;
            left: 0;
            width: 100%;
            height: 100%;
            background: rgba(0, 0, 0, 0.5);
            z-index: 9998;
            display: flex;
            align-items: center;
            justify-content: center;
            backdrop-filter: blur(4px);
            animation: fadeIn 0.2s ease;
        `;

        const width = options.width || '600px';
        const maxHeight = options.maxHeight || '80vh';

        this.modal.innerHTML = `
            <div style="background: white; border-radius: 12px;
                        box-shadow: 0 20px 60px rgba(0,0,0,0.3);
                        width: 90%; max-width: ${width}; max-height: ${maxHeight};
                        display: flex; flex-direction: column; animation: scaleIn 0.2s ease;">
                <div style="padding: 20px 24px; border-bottom: 1px solid #e5e7eb;
                            display: flex; justify-content: space-between; align-items: center;">
                    <h3 style="font-size: 18px; font-weight: 600; margin: 0; color: #0f172a;">${title}</h3>
                    <button onclick="window.modalInstance.hide()"
                            style="background: none; border: none; font-size: 24px;
                                   color: #94a3b8; cursor: pointer; padding: 0; width: 32px; height: 32px;">×</button>
                </div>
                <div style="padding: 24px; overflow-y: auto; flex: 1;">${content}</div>
                ${options.footer ? `<div style="padding: 16px 24px; border-top: 1px solid #e5e7eb;
                                             display: flex; justify-content: flex-end; gap: 12px;">
                    ${options.footer}
                </div>` : ''}
            </div>
        `;

        // Close on background click
        this.modal.addEventListener('click', (e) => {
            if (e.target === this.modal) this.hide();
        });

        document.body.appendChild(this.modal);
        window.modalInstance = this; // Make globally accessible
    }

    hide() {
        if (this.modal) {
            this.modal.style.animation = 'fadeOut 0.2s ease';
            setTimeout(() => this.modal.remove(), 200);
            this.modal = null;
        }
    }
}

// Data Export Utility
function exportToCSV(data, filename) {
    if (!data || !data.length) {
        toast.warning('No data to export');
        return;
    }

    const headers = Object.keys(data[0]);
    const csv = [
        headers.join(','),
        ...data.map(row => headers.map(h => JSON.stringify(row[h] || '')).join(','))
    ].join('\n');

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `${filename}_${new Date().toISOString().slice(0, 10)}.csv`;
    a.click();
    URL.revokeObjectURL(url);

    toast.success('Data exported successfully');
}

// Table Filter
function filterTable(tableId, searchText, column = null) {
    const table = document.getElementById(tableId);
    if (!table) return;

    const tbody = table.querySelector('tbody');
    const rows = tbody.querySelectorAll('tr');
    let visibleCount = 0;

    rows.forEach(row => {
        if (row.querySelector('.empty-state')) return;

        const cells = row.querySelectorAll('td');
        let match = false;

        if (column !== null) {
            const cell = cells[column];
            if (cell && cell.textContent.toLowerCase().includes(searchText.toLowerCase())) {
                match = true;
            }
        } else {
            Array.from(cells).forEach(cell => {
                if (cell.textContent.toLowerCase().includes(searchText.toLowerCase())) {
                    match = true;
                }
            });
        }

        row.style.display = match ? '' : 'none';
        if (match) visibleCount++;
    });

    return visibleCount;
}

// Pulse Animation
function pulseElement(elementId) {
    const el = document.getElementById(elementId);
    if (!el) return;

    el.style.animation = 'pulse 0.5s ease';
    setTimeout(() => el.style.animation = '', 500);
}

// Number Counter Animation
function animateNumber(elementId, targetValue, duration = 1000) {
    const el = document.getElementById(elementId);
    if (!el) return;

    const startValue = parseInt(el.textContent.replace(/,/g, '')) || 0;
    const diff = targetValue - startValue;
    const steps = 60;
    const stepValue = diff / steps;
    const stepDuration = duration / steps;

    let current = startValue;
    const interval = setInterval(() => {
        current += stepValue;
        if ((diff > 0 && current >= targetValue) || (diff < 0 && current <= targetValue)) {
            el.textContent = targetValue.toLocaleString();
            clearInterval(interval);
        } else {
            el.textContent = Math.round(current).toLocaleString();
        }
    }, stepDuration);
}

// Initialize global instances
const toast = new Toast();
const loading = new LoadingOverlay();
const modal = new Modal();

// Add CSS animations
const style = document.createElement('style');
style.textContent = `
    @keyframes slideIn {
        from { transform: translateX(400px); opacity: 0; }
        to { transform: translateX(0); opacity: 1; }
    }
    @keyframes slideOut {
        from { transform: translateX(0); opacity: 1; }
        to { transform: translateX(400px); opacity: 0; }
    }
    @keyframes fadeIn {
        from { opacity: 0; }
        to { opacity: 1; }
    }
    @keyframes fadeOut {
        from { opacity: 1; }
        to { opacity: 0; }
    }
    @keyframes scaleIn {
        from { transform: scale(0.9); opacity: 0; }
        to { transform: scale(1); opacity: 1; }
    }
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
    @keyframes pulse {
        0%, 100% { transform: scale(1); }
        50% { transform: scale(1.05); }
    }

    .fade-in {
        animation: fadeIn 0.3s ease;
    }

    .highlight-new {
        background: #fef3c7 !important;
        transition: background 2s ease;
    }
`;
document.head.appendChild(style);
