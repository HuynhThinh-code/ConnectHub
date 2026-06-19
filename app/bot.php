<?php
// ConnectHub Local ChatBot
// Runs in background to simulate an interactive chat partner.

require_once 'includes/db.php';

// Ensure the db connection is open
if ($conn->connect_error) {
    die("Database connection error: " . $conn->connect_error);
}

echo "ConnectHub ChatBot is starting...\n";

// 1. Ensure Antigravity user exists
$username = 'antigravity';
$email = 'antigravity@bot.local';
$pass_hash = md5('antigravity');
$full_name = 'Antigravity AI Assistant';
$bio = 'Your helpful local AI and security mentor. Type "help" to learn about my commands.';
$avatar = 'default-male.svg';

$check = $conn->query("SELECT id FROM users WHERE username = '$username'");
if ($check && $check->num_rows > 0) {
    $bot = $check->fetch_assoc();
    $bot_id = (int)$bot['id'];
    echo "Bot user found (ID: $bot_id).\n";
} else {
    $conn->query("INSERT INTO users (username, email, password, full_name, bio, avatar) VALUES ('$username', '$email', '$pass_hash', '$full_name', '$bio', '$avatar')");
    $bot_id = $conn->insert_id;
    echo "Created new Bot user (ID: $bot_id).\n";
}

// 2. Insert welcome messages for existing users if not already present
$users = $conn->query("SELECT id, username FROM users WHERE username != 'antigravity'");
if ($users) {
    while ($u = $users->fetch_assoc()) {
        $uid = (int)$u['id'];
        // Check if there is already a message thread between bot and this user
        $m_check = $conn->query("SELECT id FROM messages WHERE (sender_id = $bot_id AND receiver_id = $uid) OR (sender_id = $uid AND receiver_id = $bot_id)");
        if ($m_check && $m_check->num_rows == 0) {
            $welcome = "Hello @{$u['username']}! I am Antigravity, your local AI assistant. Let's chat! Type **help** to see all the interactive hacking tutorials I can show you.";
            $conn->query("INSERT INTO messages (sender_id, receiver_id, content) VALUES ($bot_id, $uid, '" . $conn->real_escape_string($welcome) . "')");
            echo "Sent welcome message to @{$u['username']} (ID: $uid).\n";
        }
    }
}

echo "Bot is listening for messages...\n";

// Keep track of the last processed message ID per user conversation to avoid reprocessing
$last_processed = [];

// Get the maximum message ID in the database initially to avoid replying to old historical messages
$max_id_res = $conn->query("SELECT MAX(id) AS max_id FROM messages");
$start_from_id = 0;
if ($max_id_res) {
    $row = $max_id_res->fetch_assoc();
    $start_from_id = (int)$row['max_id'];
}
echo "Listening for new messages with ID > $start_from_id...\n";

// Start main loop
while (true) {
    // Select all messages sent to bot that are newer than start_from_id
    $query = "SELECT id, sender_id, content, created_at FROM messages WHERE receiver_id = $bot_id AND id > $start_from_id ORDER BY id ASC";
    $result = $conn->query($query);
    
    if ($result && $result->num_rows > 0) {
        while ($msg = $result->fetch_assoc()) {
            $msg_id = (int)$msg['id'];
            $sender_id = (int)$msg['sender_id'];
            $content = trim($msg['content']);
            
            // Update start_from_id to prevent checking this message again
            if ($msg_id > $start_from_id) {
                $start_from_id = $msg_id;
            }
            
            echo "Received message from user $sender_id: '$content'\n";
            
            // Respond based on message text
            $response = get_bot_response($content);
            
            // Insert bot reply
            $conn->query("INSERT INTO messages (sender_id, receiver_id, content) VALUES ($bot_id, $sender_id, '" . $conn->real_escape_string($response) . "')");
            echo "Replied to user $sender_id.\n";
        }
    }
    
    // Sleep for 1 second to avoid CPU usage spikes
    sleep(1);
}

// Simple rule-based chatbot brains
function get_bot_response($input) {
    $input_lower = strtolower($input);
    
    // Command mapping
    if (strpos($input_lower, 'help') !== false || strpos($input_lower, 'command') !== false || $input_lower === '?') {
        return "🤖 **Available interactive tutorials:**\n\n" .
               "- **xss**: Exploit Stored XSS in real-time chat.\n" .
               "- **sqli**: Bypass login validation using SQL Injection.\n" .
               "- **exif**: Execute commands via profile image metadata.\n" .
               "- **ssrf**: Trigger SSRF on the URL Preview page.\n" .
               "- **idor**: Read messages belonging to other users.\n" .
               "- **secret**: Ask me a secret.\n\n" .
               "Type any of the bold terms above, and I will show you how to exploit it!";
    }
    
    if (strpos($input_lower, 'xss') !== false) {
        return "💻 **Stored XSS tutorial:**\n\n" .
               "Since my chat renderer uses `.innerHTML` to insert messages without sanitization, you can execute javascript directly on my browser!\n\n" .
               "Try copying and sending this payload to me in this chat window:\n" .
               "`<img src=x onerror=\"alert('XSS Executed! Coookies: ' + document.cookie)\">`\n\n" .
               "Once sent, the browser will try to render the invalid image, fail, and execute the Javascript payload instantly!";
    }
    
    if (strpos($input_lower, 'sqli') !== false || strpos($input_lower, 'sql injection') !== false) {
        return "🔑 **SQL Injection tutorial:**\n\n" .
               "Go to the login page (`login.php`). The backend runs a raw SQL query:\n" .
               "`SELECT * FROM users WHERE username='\$username' AND password='\$password'`\n\n" .
               "Because the inputs aren't escaped or parameterized, you can close the string quote early.\n\n" .
               "Try typing this into the **Username** field:\n" .
               "`admin' -- ` *(note the trailing space)*\n\n" .
               "Leave the password field empty and click Login. The database will process: `SELECT * FROM users WHERE username='admin'` and comment out the rest of the query, logging you in as the Administrator!";
    }
    
    if (strpos($input_lower, 'exif') !== false || strpos($input_lower, 'cmd') !== false || strpos($input_lower, 'injection') !== false && strpos($input_lower, 'command') !== false) {
        return "🐚 **Command Injection (Exiftool) tutorial:**\n\n" .
               "Go to Settings. When you upload a profile picture, the server strips metadata using `exiftool` via `shell_exec`:\n" .
               "`shell_exec(\"exiftool -all= uploads/\" . \$filename)`\n\n" .
               "Because the filename is not shell-escaped, if a file is uploaded with shell metacharacters in its name, it will execute commands!\n\n" .
               "Try renaming an image to: `photo.png;id` or `photo.png;whoami` and uploading it. The output from `exiftool` will print the system command result in the warning box!";
    }
    
    if (strpos($input_lower, 'ssrf') !== false) {
        return "🌐 **Server-Side Request Forgery (SSRF) tutorial:**\n\n" .
               "Navigate to URL Preview (`preview.php`). The server uses PHP to make a web request to any URL you enter and render its title/description.\n\n" .
               "Because it accepts any IP address or host, you can force the server to scan internal networks or query local databases (e.g. `http://127.0.0.1:3306` or `http://localhost/` pages only accessible from inside the docker containers).";
    }
    
    if (strpos($input_lower, 'idor') !== false) {
        return "👁️ **Insecure Direct Object Reference (IDOR) tutorial:**\n\n" .
               "Open the developers tool network tab and look at how messages are fetched: `/api/get_messages.php?to=<user_id>`.\n\n" .
               "Because there is no backend ownership verification checking if the logged-in user is actually authorized to converse with `<user_id>`, you can query `get_messages.php?to=2` (or other IDs) from any user account to spy on their personal communications!";
    }
    
    if (strpos($input_lower, 'secret') !== false) {
        return "🤫 **The Secret:**\n\n" .
               "Antigravity AI is always watching, pair programming, and coding with you! Happy hacking! 🚀✨";
    }
    
    if (strpos($input_lower, 'hello') !== false || strpos($input_lower, 'hi') !== false || strpos($input_lower, 'hey') !== false || strpos($input_lower, 'halo') !== false) {
        return "👋 Hello! I am **Antigravity**, your local AI chat partner. Type **help** to see all the cool security challenges and vulnerability write-ups I can guide you through!";
    }
    
    return "🤖 Tôi đã nhận được tin nhắn của bạn: *\"" . htmlspecialchars($input) . "\"*.\n\n" .
           "Tôi là một bot hướng dẫn bảo mật tự động. Hãy gõ **help** để xem danh sách các bài học tấn công bảo mật mà tôi có thể hướng dẫn bạn thực hiện trên ConnectHub nhé! 🚀";
}
