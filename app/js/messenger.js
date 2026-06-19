/**
 * ConnectHub Messenger Popup — AJAX Short Polling
 * VULN: innerHTML used without sanitization = Real-time Stored XSS demo
 */

const MessengerApp = {
    isOpen: false,
    openWindows: {}, // { userId: { lastId, pollInterval, element } }

    init() {
        if (typeof currentUserId === 'undefined') return;

        // Close panel when clicking outside messenger container
        document.addEventListener('click', (e) => {
            const container = document.getElementById('messenger-container');
            if (container && !container.contains(e.target)) {
                if (this.isOpen) this.closePanel();
            }
        });

        // Live search filter
        const searchInput = document.getElementById('messenger-search');
        if (searchInput) {
            searchInput.addEventListener('input', () => {
                const query = searchInput.value.toLowerCase();
                document.querySelectorAll('.messenger-contact-item').forEach(item => {
                    const name = item.dataset.name || '';
                    item.style.display = name.includes(query) ? 'flex' : 'none';
                });
            });
        }
    },

    togglePanel() {
        if (this.isOpen) {
            this.closePanel();
        } else {
            this.openPanel();
        }
    },

    openPanel() {
        const panel = document.getElementById('messenger-panel');
        if (!panel) return;
        this.isOpen = true;
        panel.classList.add('visible');
        this.loadContacts();
    },

    closePanel() {
        const panel = document.getElementById('messenger-panel');
        if (!panel) return;
        this.isOpen = false;
        panel.classList.remove('visible');
    },

    // ─── Load Contacts List ───────────────────────────────────────────────────
    loadContacts() {
        const list = document.getElementById('messenger-contacts');
        if (!list) return;

        fetch(`/api/get_contacts.php?_=${Date.now()}`)
            .then(r => r.json())
            .then(contacts => {
                if (!Array.isArray(contacts) || contacts.length === 0) {
                    list.innerHTML = `<div class="messenger-empty">
                        <i class="fas fa-comment-slash fa-2x" style="color:var(--muted);"></i>
                        <p>No conversations yet.</p>
                        <a href="/friends.php" style="font-weight:600; color:var(--primary);">Find friends →</a>
                    </div>`;
                    return;
                }

                list.innerHTML = '';
                contacts.forEach(c => {
                    const item = document.createElement('div');
                    item.className = 'messenger-contact-item';
                    item.dataset.userId = c.other_id;
                    item.dataset.name = (c.full_name || '').toLowerCase();
                    item.innerHTML = `
                        <div class="messenger-avatar-wrap">
                            <img src="/uploads/${c.avatar}" onerror="this.onerror=null; this.src='/uploads/default-male.svg';" alt="${c.full_name}">
                            <span class="messenger-online-dot"></span>
                        </div>
                        <div class="messenger-contact-info">
                            <div class="messenger-contact-name">${c.full_name}</div>
                            <div class="messenger-contact-status">@${c.username}</div>
                        </div>
                        <i class="fas fa-chevron-right messenger-contact-arrow"></i>
                    `;
                    item.addEventListener('click', () => {
                        this.openChat(c);
                        this.closePanel();
                    });
                    list.appendChild(item);
                });
            })
            .catch(() => {
                list.innerHTML = `<div class="messenger-empty">
                    <i class="fas fa-wifi-slash" style="color:var(--muted);"></i>
                    <p>Could not load conversations.</p>
                </div>`;
            });
    },

    // ─── Open a Chat Window ───────────────────────────────────────────────────
    openChat(contact) {
        const userId = String(contact.other_id);

        // Already open → bounce effect
        if (this.openWindows[userId]) {
            const el = this.openWindows[userId].element;
            el.classList.add('bounce');
            setTimeout(() => el.classList.remove('bounce'), 500);
            // Focus input
            const inp = document.getElementById(`chat-input-${userId}`);
            if (inp) inp.focus();
            return;
        }

        // Limit to 3 open windows, close oldest
        const keys = Object.keys(this.openWindows);
        if (keys.length >= 3) this.closeChat(keys[0]);

        // Build chat window DOM
        const chatEl = document.createElement('div');
        chatEl.className = 'messenger-chat-window';
        chatEl.id = `chat-window-${userId}`;
        chatEl.innerHTML = `
            <div class="messenger-chat-header">
                <img src="/uploads/${contact.avatar}" onerror="this.onerror=null; this.src='/uploads/default-male.svg';" alt="${contact.full_name}">
                <div class="messenger-chat-header-info">
                    <span class="messenger-chat-header-name">${contact.full_name}</span>
                    <small style="opacity:0.8; font-size:0.7rem;">Active now</small>
                </div>
                <div class="messenger-chat-header-actions">
                    <a href="/messages.php?to=${userId}" title="Open full chat" class="messenger-header-btn">
                        <i class="fas fa-up-right-from-square"></i>
                    </a>
                    <button class="messenger-header-btn messenger-chat-close"
                            onclick="MessengerApp.closeChat('${userId}')" title="Close">
                        <i class="fas fa-xmark"></i>
                    </button>
                </div>
            </div>
            <div class="messenger-chat-messages" id="chat-messages-${userId}">
                <div class="messenger-loading">
                    <i class="fas fa-spinner fa-spin"></i>
                </div>
            </div>
            <form class="messenger-chat-input" id="chat-form-${userId}"
                  onsubmit="MessengerApp.sendMessage(event, '${userId}')">
                <input type="text" id="chat-input-${userId}"
                       placeholder="Aa" autocomplete="off" required>
                <button type="submit" class="messenger-send-btn" title="Send">
                    <i class="fas fa-paper-plane"></i>
                </button>
            </form>
        `;

        document.getElementById('messenger-windows').prepend(chatEl);

        // Register in openWindows
        this.openWindows[userId] = {
            lastId: 0,
            contact,
            element: chatEl,
            pollInterval: null
        };

        // Load initial messages, then kick off polling
        this.fetchMessages(userId, true).then(() => {
            if (!this.openWindows[userId]) return;
            this.openWindows[userId].pollInterval = setInterval(() => {
                this.fetchMessages(userId, false);
            }, 2000);
        });

        // Auto-focus input
        setTimeout(() => {
            const inp = document.getElementById(`chat-input-${userId}`);
            if (inp) inp.focus();
        }, 150);
    },

    // ─── Close a Chat Window ──────────────────────────────────────────────────
    closeChat(userId) {
        userId = String(userId);
        if (!this.openWindows[userId]) return;

        clearInterval(this.openWindows[userId].pollInterval);

        const el = this.openWindows[userId].element;
        el.style.transition = 'all 0.2s ease';
        el.style.opacity = '0';
        el.style.transform = 'translateY(16px) scale(0.95)';
        setTimeout(() => el.remove(), 200);

        delete this.openWindows[userId];
    },

    // ─── Fetch Messages (Polling) ─────────────────────────────────────────────
    fetchMessages(userId, isInitial) {
        userId = String(userId);
        const win = this.openWindows[userId];
        if (!win) return Promise.resolve();

        const url = `/api/get_messages.php?to=${userId}&last_id=${win.lastId}&_=${Date.now()}`;

        return fetch(url)
            .then(r => r.json())
            .then(messages => {
                if (!this.openWindows[userId]) return;
                const box = document.getElementById(`chat-messages-${userId}`);
                if (!box) return;

                // First render: clear spinner
                if (isInitial) {
                    box.innerHTML = '';
                    if (!Array.isArray(messages) || messages.length === 0) {
                        box.innerHTML = `<div class="messenger-empty" style="font-size:0.8rem;">
                            <i class="fas fa-hand-wave" style="font-size:1.5rem; color:var(--secondary);"></i>
                            <p>Say hello! 👋</p>
                        </div>`;
                        return;
                    }
                }

                if (!Array.isArray(messages) || messages.length === 0) return;

                // Track scroll position to auto-scroll only if user was at bottom
                const atBottom = box.scrollHeight - box.clientHeight <= box.scrollTop + 20;

                messages.forEach(msg => {
                    const isSent = parseInt(msg.sender_id) === currentUserId;
                    const bubble = document.createElement('div');
                    bubble.className = `messenger-bubble ${isSent ? 'sent' : 'recv'}`;
                    // Intentionally vulnerable for the lab: renders message HTML directly.
                    bubble.innerHTML = `<div class="messenger-bubble-content">${msg.content}</div>`;
                    box.appendChild(bubble);
                    win.lastId = Math.max(win.lastId, parseInt(msg.id));
                });

                if (atBottom || isInitial) {
                    box.scrollTop = box.scrollHeight;
                }
            })
            .catch(() => {}); // Silently ignore network errors during polling
    },

    // ─── Send Message ─────────────────────────────────────────────────────────
    sendMessage(event, userId) {
        event.preventDefault();
        userId = String(userId);

        const input = document.getElementById(`chat-input-${userId}`);
        const content = input.value.trim();
        if (!content) return;

        input.value = '';
        input.disabled = true;

        // VULN: no CSRF token in this request
        fetch('/api/send_message.php', {
            method: 'POST',
            headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
            body: `receiver_id=${userId}&content=${encodeURIComponent(content)}`
        })
        .then(r => r.json())
        .then(data => {
            input.disabled = false;
            input.focus();
            if (data.status === 'ok') {
                // Immediately poll to show the sent message in bubble
                this.fetchMessages(userId, false);
            }
        })
        .catch(() => {
            input.disabled = false;
        });
    }
};

// Bootstrap on DOM ready
document.addEventListener('DOMContentLoaded', () => MessengerApp.init());
