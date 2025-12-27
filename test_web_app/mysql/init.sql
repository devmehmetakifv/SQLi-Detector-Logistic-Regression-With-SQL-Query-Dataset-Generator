-- Create users table
CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password VARCHAR(255) NOT NULL,
    email VARCHAR(100),
    role VARCHAR(20) DEFAULT 'user',
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Insert test users (passwords are plaintext for demo - NEVER do this in production!)
INSERT INTO users (username, password, email, role) VALUES
('admin', 'admin123', 'admin@company.com', 'admin'),
('john_doe', 'password123', 'john@example.com', 'user'),
('jane_smith', 'letmein', 'jane@example.com', 'user'),
('test_user', 'test1234', 'test@test.com', 'user'),
('developer', 'dev_pass!', 'dev@company.com', 'developer');

-- Create a logs table for tracking login attempts
CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username_input VARCHAR(500),
    password_input VARCHAR(500),
    ip_address VARCHAR(45),
    success BOOLEAN,
    sqli_detected BOOLEAN,
    attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
