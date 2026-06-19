<?php
// Redirect to a default avatar SVG
header('Content-Type: image/svg+xml');
echo '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100"><circle cx="50" cy="50" r="50" fill="#e2e8f0"/><circle cx="50" cy="38" r="18" fill="#94a3b8"/><ellipse cx="50" cy="90" rx="30" ry="22" fill="#94a3b8"/></svg>';
