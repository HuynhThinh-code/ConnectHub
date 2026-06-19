</div><!-- end container -->
<footer>
    <p>ConnectHub &copy; <?= date('Y') ?> — <em>Intentionally Vulnerable App — Educational Use Only</em></p>
    <div style="margin-top: 10px; font-size: 1.2rem; display: flex; justify-content: center; gap: 16px;">
        <a href="https://github.com" target="_blank" style="color: var(--muted);"><i class="fab fa-github"></i></a>
        <a href="https://google.com" target="_blank" style="color: var(--muted);"><i class="fab fa-google"></i></a>
    </div>
</footer>

<?php if (empty($_SESSION['is_admin'])) require_once __DIR__ . '/messenger_popup.php'; ?>

<script src="/js/main.js"></script>
<script src="/js/messenger.js"></script>
</body>
</html>
