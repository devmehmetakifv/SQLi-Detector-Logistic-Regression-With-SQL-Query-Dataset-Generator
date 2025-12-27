<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>SQLi Demo - Vulnerable Login</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdn.jsdelivr.net/npm/bootstrap-icons@1.11.1/font/bootstrap-icons.css" rel="stylesheet">
    <style>
        :root {
            --gradient-start: #667eea;
            --gradient-end: #764ba2;
        }
        
        body {
            min-height: 100vh;
            background: linear-gradient(135deg, var(--gradient-start) 0%, var(--gradient-end) 100%);
            font-family: 'Segoe UI', system-ui, sans-serif;
        }
        
        .login-container {
            min-height: 100vh;
            display: flex;
            align-items: center;
            justify-content: center;
            padding: 20px;
        }
        
        .login-card {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 20px;
            box-shadow: 0 25px 50px rgba(0, 0, 0, 0.25);
            max-width: 900px;
            width: 100%;
            overflow: hidden;
        }
        
        .login-header {
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .login-header h1 {
            font-weight: 700;
            margin-bottom: 10px;
        }
        
        .warning-badge {
            background: #dc3545;
            color: white;
            padding: 5px 15px;
            border-radius: 20px;
            font-size: 0.85rem;
            display: inline-block;
        }
        
        .login-body {
            padding: 40px;
        }
        
        .form-floating > .form-control {
            border-radius: 12px;
            border: 2px solid #e0e0e0;
            padding: 1rem 1rem;
        }
        
        .form-floating > .form-control:focus {
            border-color: var(--gradient-start);
            box-shadow: 0 0 0 4px rgba(102, 126, 234, 0.15);
        }
        
        .btn-login {
            background: linear-gradient(135deg, var(--gradient-start) 0%, var(--gradient-end) 100%);
            border: none;
            border-radius: 12px;
            padding: 15px;
            font-weight: 600;
            font-size: 1.1rem;
            transition: all 0.3s ease;
        }
        
        .btn-login:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 25px rgba(102, 126, 234, 0.4);
        }
        
        /* Model Results Section */
        .model-results {
            background: #f8f9fa;
            border-radius: 15px;
            padding: 25px;
            margin-top: 30px;
        }
        
        .model-card {
            background: white;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 15px;
            border-left: 5px solid #6c757d;
            transition: all 0.3s ease;
        }
        
        .model-card.detected {
            border-left-color: #dc3545;
            background: #fff5f5;
        }
        
        .model-card.safe {
            border-left-color: #28a745;
            background: #f0fff4;
        }
        
        .model-name {
            font-weight: 700;
            font-size: 1.1rem;
            margin-bottom: 8px;
        }
        
        .model-result {
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .result-icon {
            font-size: 1.5rem;
        }
        
        .result-text {
            font-weight: 600;
        }
        
        .probability-bar {
            height: 8px;
            background: #e9ecef;
            border-radius: 4px;
            margin-top: 10px;
            overflow: hidden;
        }
        
        .probability-fill {
            height: 100%;
            border-radius: 4px;
            transition: width 0.5s ease;
        }
        
        .probability-fill.high {
            background: linear-gradient(90deg, #dc3545, #ff6b6b);
        }
        
        .probability-fill.low {
            background: linear-gradient(90deg, #28a745, #51cf66);
        }
        
        /* SQL Query Display */
        .sql-display {
            background: #1a1a2e;
            color: #00ff88;
            border-radius: 10px;
            padding: 20px;
            font-family: 'Consolas', monospace;
            margin-top: 20px;
            word-break: break-all;
        }
        
        .sql-keyword {
            color: #ff79c6;
        }
        
        .sql-string {
            color: #f1fa8c;
        }
        
        /* Login Result */
        .login-result {
            padding: 20px;
            border-radius: 12px;
            margin-top: 20px;
            text-align: center;
        }
        
        .login-result.success {
            background: linear-gradient(135deg, #28a745, #20c997);
            color: white;
        }
        
        .login-result.failed {
            background: linear-gradient(135deg, #6c757d, #495057);
            color: white;
        }
        
        .user-info {
            background: white;
            border-radius: 10px;
            padding: 15px;
            margin-top: 15px;
            color: #1a1a2e;
        }
    </style>
</head>
<body>

<?php
// Configuration
$db_host = getenv('DB_HOST') ?: 'mysql';
$db_name = getenv('DB_NAME') ?: 'vulnerable_app';
$db_user = getenv('DB_USER') ?: 'app_user';
$db_pass = getenv('DB_PASS') ?: 'app_password123';
$api_url = getenv('API_URL') ?: 'http://api:5000';

$login_attempted = false;
$login_success = false;
$user_data = null;
$model_predictions = null;
$executed_query = '';
$constructed_query = '';
$error_message = '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $login_attempted = true;
    $username = $_POST['username'] ?? '';
    $password = $_POST['password'] ?? '';

    // Build the vulnerable query string once so we can reuse it for DB and model scoring
    $constructed_query = "SELECT * FROM users WHERE username = '$username' AND password = '$password'";
    
    // Step 1: Call ML API to analyze input
    $api_data = json_encode([
        'inputs' => [
            ['id' => 'raw_payload', 'text' => $username],
            ['id' => 'full_query', 'text' => $constructed_query]
        ]
    ]);
    $ch = curl_init($api_url . '/predict');
    curl_setopt_array($ch, [
        CURLOPT_POST => true,
        CURLOPT_POSTFIELDS => $api_data,
        CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
        CURLOPT_RETURNTRANSFER => true,
        CURLOPT_TIMEOUT => 10
    ]);
    $api_response = curl_exec($ch);
    $curl_error = curl_error($ch);
    curl_close($ch);
    
    if ($api_response) {
        $model_predictions = json_decode($api_response, true);
    } else {
        $model_predictions = ['error' => 'API unavailable: ' . $curl_error];
    }
    
    // Step 2: Execute VULNERABLE SQL query (intentionally insecure!)
    try {
        $conn = new mysqli($db_host, $db_user, $db_pass, $db_name);
        
        if ($conn->connect_error) {
            throw new Exception("Database connection failed: " . $conn->connect_error);
        }
        
        // ⚠️ INTENTIONALLY VULNERABLE QUERY - DO NOT USE IN PRODUCTION!
        $executed_query = $constructed_query;
        
        $result = $conn->query($executed_query);
        
        if ($result && $result->num_rows > 0) {
            $login_success = true;
            $user_data = $result->fetch_assoc();
        }
        
        $conn->close();
    } catch (Exception $e) {
        $error_message = $e->getMessage();
    }
}
?>

<div class="login-container">
    <div class="login-card">
        <div class="login-header">
            <h1><i class="bi bi-shield-exclamation"></i> SQLi Demo</h1>
            <p class="mb-2">Vulnerable Login System for Testing</p>
            <span class="warning-badge"><i class="bi bi-exclamation-triangle"></i> Intentionally Vulnerable</span>
        </div>
        
        <div class="login-body">
            <div class="row">
                <!-- Login Form Column -->
                <div class="col-lg-5">
                    <h4 class="mb-4"><i class="bi bi-person-lock"></i> Login</h4>
                    
                    <form method="POST" action="">
                        <div class="form-floating mb-3">
                            <input type="text" class="form-control" id="username" name="username" 
                                   placeholder="Username" value="<?= htmlspecialchars($_POST['username'] ?? '') ?>">
                            <label for="username"><i class="bi bi-person"></i> Username</label>
                        </div>
                        
                        <div class="form-floating mb-4">
                            <input type="password" class="form-control" id="password" name="password" 
                                   placeholder="Password">
                            <label for="password"><i class="bi bi-key"></i> Password</label>
                        </div>
                        
                        <button type="submit" class="btn btn-login btn-primary w-100">
                            <i class="bi bi-box-arrow-in-right"></i> Login
                        </button>
                    </form>
                    
                    <!-- Hint Box -->
                    <div class="alert alert-info mt-4" role="alert">
                        <h6><i class="bi bi-lightbulb"></i> Test Credentials</h6>
                        <small>
                            <code>admin / admin123</code><br>
                            <code>john_doe / password123</code>
                        </small>
                    </div>
                    
                    <div class="alert alert-warning mt-3" role="alert">
                        <h6><i class="bi bi-bug"></i> Try SQLi Payloads</h6>
                        <small>
                            <code>' OR '1'='1' --</code><br>
                            <code>admin'--</code><br>
                            <code>' UNION SELECT * FROM users --</code><br>
                            <code>1' OR '1'='1</code><br>
                            <code>1' OR 1=1-- -</code><br>
                            <code>' OR 1=1#</code><br>
                            <code>' OR 1=1/*</code><br>
                            <code>admin' OR 'x'='x</code><br>
                            <code>admin') OR ('1'='1</code><br>
                            <code>test' OR '1'='1' -- -</code><br>
                            <code>' OR SLEEP(3)--</code><br>
                            <code>1' AND (SELECT 1 FROM dual)--</code><br>
                            <code>1; DROP TABLE users;--</code><br>
                            <code>%27%20OR%201%3D1--</code><br>
                            <code>admin'/**/OR/**/'1'='1</code><br>
                            <code>admin' UNION SELECT null,null,null--</code><br>
                            <code>admin' UNION SELECT user(),database(),version()--</code><br>
                            <code>') OR ('a'='a</code><br>
                            <code>admin')) OR TRUE--</code>
                        </small>
                    </div>
                </div>
                
                <!-- Results Column -->
                <div class="col-lg-7">
                    <?php if ($login_attempted): ?>
                        
                        <!-- Model Predictions -->
                        <div class="model-results">
                            <h5 class="mb-3"><i class="bi bi-robot"></i> ML Model Detection Results</h5>
                            
                            <?php if (isset($model_predictions['predictions'])): ?>
                                <?php foreach ($model_predictions['predictions'] as $gen => $pred): ?>
                                    <?php 
                                    $detected = $pred['detected'] ?? false;
                                    $prob = $pred['probability'] ?? 0;
                                    $probPercent = round($prob * 100, 1);
                                    ?>
                                    <div class="model-card <?= $detected ? 'detected' : 'safe' ?>">
                                        <div class="model-name">
                                            <?= strtoupper($gen) ?> 
                                            <small class="text-muted">(Generation <?= substr($gen, 3) ?>)</small>
                                        </div>
                                        <div class="model-result">
                                            <span class="result-icon">
                                                <?php if ($detected): ?>
                                                    <i class="bi bi-shield-x text-danger"></i>
                                                <?php else: ?>
                                                    <i class="bi bi-shield-check text-success"></i>
                                                <?php endif; ?>
                                            </span>
                                            <span class="result-text <?= $detected ? 'text-danger' : 'text-success' ?>">
                                                <?= $detected ? 'SQLi Attack Detected!' : 'No Attack Detected' ?>
                                            </span>
                                            <span class="badge bg-secondary ms-auto"><?= $probPercent ?>%</span>
                                        </div>
                                        <div class="probability-bar">
                                            <div class="probability-fill <?= $prob > 0.5 ? 'high' : 'low' ?>" 
                                                 style="width: <?= $probPercent ?>%"></div>
                                        </div>
                                    </div>
                            <?php endforeach; ?>
                        <?php elseif (isset($model_predictions['error'])): ?>
                            <div class="alert alert-danger">
                                <i class="bi bi-exclamation-circle"></i> 
                                <?= htmlspecialchars($model_predictions['error']) ?>
                            </div>
                        <?php elseif (isset($model_predictions['inputs'])): ?>
                            <?php
                                $rawPreds = [];
                                $queryPreds = [];
                                $rawText = '';
                                $queryText = '';
                                $allModels = [];

                                foreach ($model_predictions['inputs'] as $inputBlock) {
                                    if (!isset($inputBlock['id'])) {
                                        continue;
                                    }
                                    $preds = $inputBlock['predictions'] ?? [];
                                    $allModels = array_unique(array_merge($allModels, array_keys($preds)));
                                    if ($inputBlock['id'] === 'raw_payload') {
                                        $rawPreds = $preds;
                                        $rawText = $inputBlock['text'] ?? '';
                                    } elseif ($inputBlock['id'] === 'full_query') {
                                        $queryPreds = $preds;
                                        $queryText = $inputBlock['text'] ?? '';
                                    }
                                }
                            ?>
                            <?php
                                sort($allModels);
                                foreach ($allModels as $gen):
                            ?>
                                <?php 
                                    $raw = $rawPreds[$gen] ?? null;
                                    $full = $queryPreds[$gen] ?? null;
                                ?>
                                <div class="model-card <?= ($raw && ($raw['detected'] ?? false)) || ($full && ($full['detected'] ?? false)) ? 'detected' : 'safe' ?>">
                                    <div class="model-name">
                                        <?= strtoupper($gen) ?> 
                                        <small class="text-muted">(Generation <?= substr($gen, 3) ?>)</small>
                                    </div>
                                    
                                    <?php if ($raw): ?>
                                        <?php 
                                            $rawDetected = $raw['detected'] ?? false;
                                            $rawProb = round(($raw['probability'] ?? 0) * 100, 1);
                                        ?>
                                        <div class="model-result">
                                            <span class="badge bg-secondary">Payload</span>
                                            <span class="result-icon">
                                                <?= $rawDetected ? '<i class="bi bi-shield-x text-danger"></i>' : '<i class="bi bi-shield-check text-success"></i>' ?>
                                            </span>
                                            <span class="result-text <?= $rawDetected ? 'text-danger' : 'text-success' ?>">
                                                <?= $rawDetected ? 'SQLi Detected' : 'No Attack' ?>
                                            </span>
                                            <span class="badge bg-dark ms-auto"><?= $rawProb ?>%</span>
                                        </div>
                                        <small class="text-muted d-block mb-2"><code><?= htmlspecialchars($rawText) ?></code></small>
                                        <div class="probability-bar mb-3">
                                            <div class="probability-fill <?= ($raw['probability'] ?? 0) > 0.5 ? 'high' : 'low' ?>" 
                                                 style="width: <?= $rawProb ?>%"></div>
                                        </div>
                                    <?php endif; ?>

                                    <?php if ($full): ?>
                                        <?php 
                                            $fullDetected = $full['detected'] ?? false;
                                            $fullProb = round(($full['probability'] ?? 0) * 100, 1);
                                        ?>
                                        <div class="model-result">
                                            <span class="badge bg-secondary">Full Query</span>
                                            <span class="result-icon">
                                                <?= $fullDetected ? '<i class="bi bi-shield-x text-danger"></i>' : '<i class="bi bi-shield-check text-success"></i>' ?>
                                            </span>
                                            <span class="result-text <?= $fullDetected ? 'text-danger' : 'text-success' ?>">
                                                <?= $fullDetected ? 'SQLi Detected' : 'No Attack' ?>
                                            </span>
                                            <span class="badge bg-dark ms-auto"><?= $fullProb ?>%</span>
                                        </div>
                                        <small class="text-muted d-block mb-2"><code><?= htmlspecialchars($queryText) ?></code></small>
                                        <div class="probability-bar">
                                            <div class="probability-fill <?= ($full['probability'] ?? 0) > 0.5 ? 'high' : 'low' ?>" 
                                                 style="width: <?= $fullProb ?>%"></div>
                                        </div>
                                    <?php endif; ?>
                                </div>
                            <?php endforeach; ?>
                        <?php endif; ?>
                    </div>
                    
                        <!-- Executed SQL Query -->
                        <div class="sql-display">
                            <small class="text-muted d-block mb-2">Executed SQL Query:</small>
                            <code><?= htmlspecialchars($executed_query) ?></code>
                        </div>
                        
                        <!-- Login Result -->
                        <?php if ($error_message): ?>
                            <div class="alert alert-danger mt-3">
                                <i class="bi bi-database-x"></i> <?= htmlspecialchars($error_message) ?>
                            </div>
                        <?php elseif ($login_success): ?>
                            <div class="login-result success">
                                <h4><i class="bi bi-check-circle"></i> Login Successful!</h4>
                                <p>You bypassed authentication<?= (isset($model_predictions['predictions']) || isset($model_predictions['inputs'])) ? ' (but models knew!)' : '' ?></p>
                                
                                <?php if ($user_data): ?>
                                    <div class="user-info">
                                        <strong>Logged in as:</strong><br>
                                        <i class="bi bi-person"></i> <?= htmlspecialchars($user_data['username']) ?><br>
                                        <i class="bi bi-envelope"></i> <?= htmlspecialchars($user_data['email'] ?? 'N/A') ?><br>
                                        <i class="bi bi-person-badge"></i> Role: <?= htmlspecialchars($user_data['role'] ?? 'user') ?>
                                    </div>
                                <?php endif; ?>
                            </div>
                        <?php else: ?>
                            <div class="login-result failed">
                                <h4><i class="bi bi-x-circle"></i> Login Failed</h4>
                                <p>Invalid credentials or attack blocked</p>
                            </div>
                        <?php endif; ?>
                        
                    <?php else: ?>
                        <div class="text-center text-muted py-5">
                            <i class="bi bi-arrow-left-circle" style="font-size: 3rem;"></i>
                            <h5 class="mt-3">Enter credentials to see detection results</h5>
                            <p>Try SQLi payloads to test the models!</p>
                        </div>
                    <?php endif; ?>
                </div>
            </div>
        </div>
    </div>
</div>

<script src="https://cdn.jsdelivr.net/npm/bootstrap@5.3.2/dist/js/bootstrap.bundle.min.js"></script>
</body>
</html>
