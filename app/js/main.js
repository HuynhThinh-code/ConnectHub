// ConnectHub JS — minimal, intentionally no XSS protection
// VULN: innerHTML used without sanitization in dynamic content
document.addEventListener('DOMContentLoaded', function() {
    // Auto-dismiss alerts with smooth slide-up
    const alerts = document.querySelectorAll('.alert');
    alerts.forEach(function(alert) {
        if (alert.classList.contains('session-conflict-notice')) return;

        setTimeout(function() {
            alert.style.opacity = '0';
            alert.style.transform = 'translateY(-10px)';
            alert.style.transition = 'opacity 0.4s ease, transform 0.4s ease';
            setTimeout(function() { alert.remove(); }, 400);
        }, 4000);
    });

    // Mobile menu toggle
    const mobileMenuBtn = document.getElementById('mobileMenuBtn');
    const navLinks = document.getElementById('navLinks');
    if (mobileMenuBtn && navLinks) {
        mobileMenuBtn.addEventListener('click', function() {
            navLinks.classList.toggle('mobile-show');
            const icon = mobileMenuBtn.querySelector('i');
            if (navLinks.classList.contains('mobile-show')) {
                icon.className = 'fas fa-xmark';
            } else {
                icon.className = 'fas fa-bars';
            }
        });
    }

    // Dynamic nav active highlight logic (fallback if server check misses)
    const currentPath = window.location.pathname;
    const navLinksList = document.querySelectorAll('.nav-links a');
    navLinksList.forEach(link => {
        const linkPath = link.getAttribute('href');
        if (linkPath && currentPath.endsWith(linkPath)) {
            navLinksList.forEach(l => l.classList.remove('active'));
            link.classList.add('active');
        }
    });

    // Micro-interactions: Card scale on hover (visual only)
    const cards = document.querySelectorAll('.card');
    cards.forEach(card => {
        card.addEventListener('mouseenter', () => {
            // Can add subtle effects dynamically if needed
        });
    });

    // Password visibility toggles for login/register forms
    document.querySelectorAll('.password-field').forEach(field => {
        const input = field.querySelector('input[type="password"], input[type="text"]');
        const button = field.querySelector('.password-toggle');
        const icon = button ? button.querySelector('i') : null;
        if (!input || !button || !icon) return;

        button.addEventListener('click', () => {
            const showing = input.type === 'text';
            input.type = showing ? 'password' : 'text';
            icon.className = showing ? 'fas fa-eye' : 'fas fa-eye-slash';
            button.setAttribute('aria-label', showing ? 'Show password' : 'Hide password');
            button.setAttribute('title', showing ? 'Show password' : 'Hide password');
        });
    });

    // Keep the current tab in sync with the server-side single-session rule.
    // If the same account logs in elsewhere, this tab is redirected to the login notice.
    if (!window.__connectHubSessionHeartbeat) {
        window.__connectHubSessionHeartbeat = true;
        setInterval(function() {
            fetch('/api/session_status.php', {
                cache: 'no-store',
                credentials: 'same-origin'
            })
                .then(function(response) {
                    if (response.redirected && response.url.indexOf('logged_out_elsewhere=1') !== -1) {
                        window.location.href = response.url;
                        return null;
                    }

                    const contentType = response.headers.get('content-type') || '';
                    if (contentType.indexOf('application/json') === -1) return null;
                    return response.json();
                })
                .then(function(data) {
                    if (data && data.status === 'logged_out_elsewhere') {
                        window.location.href = '/login.php?logged_out_elsewhere=1';
                    }
                })
                .catch(function() {});
        }, 8000);
    }
});
