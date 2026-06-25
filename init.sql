SET NAMES utf8mb4;
CREATE DATABASE IF NOT EXISTS connecthub CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE connecthub;

-- Users table (weak password storage = MD5)
CREATE TABLE users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    email VARCHAR(100) UNIQUE NOT NULL,
    password VARCHAR(255) NOT NULL,
    full_name VARCHAR(100),
    gender ENUM('male','female') DEFAULT 'male',
    bio TEXT,
    avatar VARCHAR(255) DEFAULT 'default-male.svg',
    -- VULN: session token stored in DB, weak/predictable
    session_token VARCHAR(64),
    oauth_provider VARCHAR(20),
    oauth_id VARCHAR(100),
    -- VULN: OAuth scope not validated
    oauth_scope VARCHAR(255) DEFAULT 'read',
    is_admin TINYINT(1) DEFAULT 0,
    is_banned TINYINT(1) DEFAULT 0,
    ban_reason VARCHAR(255),
    banned_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Posts table
CREATE TABLE posts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    content TEXT NOT NULL,
    image VARCHAR(255),
    is_private TINYINT(1) DEFAULT 0,
    status ENUM('pending','approved','rejected') DEFAULT 'approved',
    moderation_note TEXT,
    moderated_by INT,
    moderated_at TIMESTAMP NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Comments table
CREATE TABLE comments (
    id INT AUTO_INCREMENT PRIMARY KEY,
    post_id INT NOT NULL,
    user_id INT NOT NULL,
    -- VULN: content not sanitized = Stored XSS
    content TEXT NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (post_id) REFERENCES posts(id),
    FOREIGN KEY (user_id) REFERENCES users(id)
);

-- Messages table (private messaging)
CREATE TABLE messages (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    -- VULN: content not sanitized
    content TEXT NOT NULL,
    is_read TINYINT(1) DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
);

-- Friend requests table
CREATE TABLE friend_requests (
    id INT AUTO_INCREMENT PRIMARY KEY,
    sender_id INT NOT NULL,
    receiver_id INT NOT NULL,
    status ENUM('pending','accepted','rejected') DEFAULT 'pending',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (sender_id) REFERENCES users(id),
    FOREIGN KEY (receiver_id) REFERENCES users(id)
);

-- URL previews log (for SSRF)
CREATE TABLE url_previews (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT,
    url TEXT NOT NULL,
    result TEXT,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Security events log for admin intrusion monitoring
CREATE TABLE security_events (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NULL,
    actor_username VARCHAR(80),
    ip_address VARCHAR(64),
    user_agent VARCHAR(255),
    event_type VARCHAR(80) NOT NULL,
    severity ENUM('low','medium','high','critical') DEFAULT 'medium',
    request_uri TEXT,
    payload TEXT,
    details TEXT,
    resolved_at TIMESTAMP NULL,
    resolved_by INT NULL,
    ai_fixed_at DATETIME NULL,
    ai_fix_summary TEXT NULL,
    deleted_at DATETIME NULL,
    occurred_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- AI Fix rules created from admin remediation actions
CREATE TABLE ai_fix_rules (
    id INT AUTO_INCREMENT PRIMARY KEY,
    event_type VARCHAR(80) NOT NULL,
    route VARCHAR(255) NOT NULL,
    source_name VARCHAR(120) DEFAULT 'GitHub Security Lab SecLab Taskflow Agent',
    source_url VARCHAR(255) DEFAULT 'https://github.com/GitHubSecurityLab/seclab-taskflow-agent',
    fix_summary TEXT,
    is_active TINYINT(1) DEFAULT 1,
    created_by INT NULL,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    UNIQUE KEY uniq_event_route (event_type, route)
);

-- Seed data
INSERT INTO users (username, email, password, full_name, gender, bio, avatar, is_admin) VALUES
('admin', 'admin@connecthub.local', MD5('admin123'), 'Administrator', 'male', 'System admin', 'default-male.svg', 1),
('alice', 'alice@example.com', MD5('alice123'), 'Alice Johnson', 'female', 'Love photography', 'default-female.svg', 0),
('bob', 'bob@example.com', MD5('bob123'), 'Bob Smith', 'male', 'Coffee & Code', 'default-male.svg', 0),
('charlie', 'charlie@example.com', MD5('charlie123'), 'Charlie Brown', 'male', 'Security researcher', 'default-male.svg', 0);

INSERT INTO posts (user_id, content, is_private, status) VALUES
(2, 'Hello ConnectHub! Excited to be here', 0, 'approved'),
(2, 'This is my private post with sensitive info: secret_key=ABC123', 1, 'approved'),
(3, 'Working on a new project today', 0, 'approved'),
(4, 'Security tip: always sanitize your inputs!', 0, 'approved');

INSERT INTO comments (post_id, user_id, content) VALUES
(1, 3, 'Welcome Alice!'),
(1, 4, 'Great to have you here!'),
(3, 2, 'What project are you working on?');

INSERT INTO messages (sender_id, receiver_id, content) VALUES
(2, 3, 'Chào Bob, hôm nay bạn khỏe không?'),
(3, 2, 'Chào Alice! Mình vẫn ổn, còn bạn?'),
(2, 4, 'Charlie, can you review my code?'),
(1, 2, 'Admin message: Your account has been verified');

INSERT INTO friend_requests (sender_id, receiver_id, status) VALUES
(2, 3, 'accepted'),
(2, 4, 'pending'),
(3, 4, 'accepted');
