<?php if (isset($_SESSION['user_id'])): ?>
<!-- Messenger Popup — ConnectHub -->
<div id="messenger-container">

    <!-- Chat windows (multiple side by side, grow left) -->
    <div id="messenger-windows"></div>

    <!-- Contacts Panel (slides up from button) -->
    <div id="messenger-panel">
        <div class="messenger-panel-header">
            <i class="fas fa-comment-dots"></i>
            <h4>Messages</h4>
            <button onclick="MessengerApp.togglePanel()" class="messenger-panel-close-btn" aria-label="Close">
                <i class="fas fa-xmark"></i>
            </button>
        </div>
        <div class="messenger-panel-search">
            <i class="fas fa-magnifying-glass"></i>
            <input type="text" id="messenger-search" placeholder="Search conversations..." autocomplete="off">
        </div>
        <div id="messenger-contacts">
            <div class="messenger-loading">
                <i class="fas fa-spinner fa-spin"></i> Loading...
            </div>
        </div>
    </div>

    <!-- Floating Bubble Button -->
    <button id="messenger-toggle" onclick="MessengerApp.togglePanel()" aria-label="Open Messenger" title="Messages">
        <i class="fas fa-comment-dots"></i>
        <span id="messenger-unread-badge" style="display:none;">0</span>
    </button>
</div>

<script>
    // Pass PHP session data to JS securely
    const currentUserId = <?= (int)$_SESSION['user_id'] ?>;
</script>
<?php endif; ?>
