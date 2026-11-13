<?php
declare(strict_types=1);

require_once __DIR__ . '/config.php';

function respond(array $body, int $status = 200): void
{
    http_response_code($status);
    header('Content-Type: application/json; charset=utf-8');
    header('Cache-Control: no-store');
    echo json_encode($body, JSON_UNESCAPED_UNICODE | JSON_UNESCAPED_SLASHES);
    exit;
}

function request_data(): array
{
    $raw = file_get_contents('php://input');
    if ($raw === '' || $raw === false) {
        return [];
    }

    $data = json_decode($raw, true);
    if (!is_array($data)) {
        respond(['error' => 'The request body must be valid JSON.'], 400);
    }
    return $data;
}

function require_csrf(): void
{
    $provided = $_SERVER['HTTP_X_CSRF_TOKEN'] ?? '';
    $expected = $_SESSION['csrf_token'] ?? '';
    if ($expected === '' || !hash_equals($expected, $provided)) {
        respond(['error' => 'Your session expired. Reload the page and try again.'], 403);
    }
}

function require_user(PDO $pdo, ?string $role = null): array
{
    $userId = $_SESSION['user_id'] ?? null;
    if (!is_int($userId) && !ctype_digit((string)$userId)) {
        respond(['error' => 'Please log in to continue.'], 401);
    }

    $stmt = $pdo->prepare('SELECT id, full_name AS name, username AS u, role FROM users WHERE id = ?');
    $stmt->execute([(int)$userId]);
    $user = $stmt->fetch();
    if (!$user) {
        unset($_SESSION['user_id']);
        respond(['error' => 'Please log in to continue.'], 401);
    }
    $user['id'] = (int)$user['id'];
    if ($role !== null && $user['role'] !== $role) {
        respond(['error' => 'You do not have permission to perform this action.'], 403);
    }
    return $user;
}

function valid_account_fields(array $data): array
{
    $name = trim((string)($data['name'] ?? ''));
    $username = trim((string)($data['username'] ?? ''));
    $password = (string)($data['password'] ?? '');

    if ($name === '' || strlen($name) > 120) {
        respond(['error' => 'Enter a full name of up to 120 characters.'], 400);
    }
    if (!preg_match('/^[A-Za-z0-9._-]{3,64}$/', $username)) {
        respond(['error' => 'Username must be 3–64 characters using letters, numbers, dots, underscores or hyphens.'], 400);
    }
    if (strlen($password) < 6 || strlen($password) > 1024) {
        respond(['error' => 'Password must be at least 6 characters.'], 400);
    }
    return [$name, $username, $password];
}

function insert_user(PDO $pdo, string $name, string $username, string $password, string $role): int
{
    $stmt = $pdo->prepare(
        'INSERT INTO users (full_name, username, password_hash, role) VALUES (?, ?, ?, ?)'
    );
    $stmt->execute([$name, $username, password_hash($password, PASSWORD_DEFAULT), $role]);
    return (int)$pdo->lastInsertId();
}

function establish_session(int $userId): void
{
    session_regenerate_id(true);
    $_SESSION['user_id'] = $userId;
}

function has_admin(PDO $pdo): bool
{
    $stmt = $pdo->query("SELECT admin_created FROM system_settings WHERE singleton = 1");
    $setting = $stmt->fetch();
    if (!$setting) {
        throw new RuntimeException('BirthTrack settings row is missing.');
    }
    if ((int)$setting['admin_created'] === 1) {
        return true;
    }
    return (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role = 'admin'")->fetchColumn() > 0;
}

function create_public_user(PDO $pdo, array $data, string $role): void
{
    [$name, $username, $password] = valid_account_fields($data);
    try {
        $userId = insert_user($pdo, $name, $username, $password, $role);
    } catch (PDOException $error) {
        if ($error->getCode() === '23000') {
            respond(['error' => 'That username is already taken.'], 409);
        }
        throw $error;
    }
    establish_session($userId);
    respond(['user' => ['id' => $userId, 'name' => $name, 'u' => $username, 'role' => $role]]);
}

$https = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] !== 'off';
session_set_cookie_params([
    'httponly' => true,
    'secure' => $https,
    'samesite' => 'Lax',
    'path' => '/',
]);
session_start();
if (!isset($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

try {
    $pdo = birthtrack_db();
    $action = (string)($_GET['action'] ?? '');
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';

    if ($action === 'bootstrap' && $method === 'GET') {
        respond([
            'csrfToken' => $_SESSION['csrf_token'],
            'setupRequired' => !has_admin($pdo),
        ]);
    }

    if ($action === 'login' && $method === 'POST') {
        require_csrf();
        $data = request_data();
        $username = trim((string)($data['username'] ?? ''));
        $password = (string)($data['password'] ?? '');
        $stmt = $pdo->prepare('SELECT id, password_hash FROM users WHERE username = ?');
        $stmt->execute([$username]);
        $user = $stmt->fetch();
        if (!$user || !password_verify($password, $user['password_hash'])) {
            respond(['error' => 'Invalid username or password.'], 401);
        }
        establish_session((int)$user['id']);
        respond(['ok' => true]);
    }

    if ($action === 'setup' && $method === 'POST') {
        require_csrf();
        [$name, $username, $password] = valid_account_fields(request_data());
        $pdo->beginTransaction();
        $setting = $pdo->query('SELECT admin_created FROM system_settings WHERE singleton = 1 FOR UPDATE')->fetch();
        if (!$setting) {
            $pdo->rollBack();
            respond(['error' => 'Database is not initialized. Import database.sql first.'], 500);
        }
        $existingAdmin = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role = 'admin'")->fetchColumn() > 0;
        if ((int)$setting['admin_created'] === 1 || $existingAdmin) {
            $pdo->rollBack();
            respond(['error' => 'An administrator account has already been created.'], 409);
        }
        try {
            $userId = insert_user($pdo, $name, $username, $password, 'admin');
            $pdo->exec('UPDATE system_settings SET admin_created = 1 WHERE singleton = 1');
            $pdo->commit();
        } catch (PDOException $error) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if ($error->getCode() === '23000') {
                respond(['error' => 'That username is already taken.'], 409);
            }
            throw $error;
        }
        establish_session($userId);
        respond(['ok' => true]);
    }

    if ($action === 'register' && $method === 'POST') {
        require_csrf();
        create_public_user($pdo, request_data(), 'applicant');
    }

    if ($action === 'me' && $method === 'GET') {
        $userId = $_SESSION['user_id'] ?? null;
        if (!$userId) {
            respond(['user' => null]);
        }
        $stmt = $pdo->prepare('SELECT id, full_name AS name, username AS u, role FROM users WHERE id = ?');
        $stmt->execute([(int)$userId]);
        $user = $stmt->fetch();
        if (!$user) {
            unset($_SESSION['user_id']);
            respond(['user' => null]);
        }
        $user['id'] = (int)$user['id'];
        respond(['user' => $user]);
    }

    if ($action === 'logout' && $method === 'POST') {
        require_csrf();
        $_SESSION = [];
        if (ini_get('session.use_cookies')) {
            $params = session_get_cookie_params();
            setcookie(session_name(), '', time() - 42000, $params['path'], '', $params['secure'], $params['httponly']);
        }
        session_destroy();
        respond(['ok' => true]);
    }

    if ($action === 'users' && $method === 'GET') {
        require_user($pdo, 'admin');
        $users = $pdo->query('SELECT id, full_name AS name, username AS u, role FROM users ORDER BY id')->fetchAll();
        foreach ($users as &$user) {
            $user['id'] = (int)$user['id'];
        }
        unset($user);
        respond(['users' => $users]);
    }

    if ($action === 'users' && $method === 'POST') {
        require_csrf();
        require_user($pdo, 'admin');
        $data = request_data();
        $role = (string)($data['role'] ?? '');
        if (!in_array($role, ['admin', 'clerk'], true)) {
            respond(['error' => 'Choose an administrator or registration clerk role.'], 400);
        }
        [$name, $username, $password] = valid_account_fields($data);
        try {
            insert_user($pdo, $name, $username, $password, $role);
        } catch (PDOException $error) {
            if ($error->getCode() === '23000') {
                respond(['error' => 'That username is already taken.'], 409);
            }
            throw $error;
        }
        respond(['ok' => true]);
    }

    if ($action === 'users' && $method === 'DELETE') {
        require_csrf();
        $current = require_user($pdo, 'admin');
        $id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);
        if (!$id || $id === $current['id']) {
            respond(['error' => 'Select another valid account to delete.'], 400);
        }
        $stmt = $pdo->prepare('SELECT role FROM users WHERE id = ?');
        $stmt->execute([$id]);
        $target = $stmt->fetch();
        if (!$target) {
            respond(['error' => 'That account no longer exists.'], 404);
        }
        if ($target['role'] === 'admin') {
            $count = (int)$pdo->query("SELECT COUNT(*) FROM users WHERE role = 'admin'")->fetchColumn();
            if ($count <= 1) {
                respond(['error' => 'The last administrator account cannot be deleted.'], 409);
            }
        }
        $stmt = $pdo->prepare('DELETE FROM users WHERE id = ?');
        $stmt->execute([$id]);
        respond(['ok' => true]);
    }

    if ($action === 'applications' && $method === 'GET') {
        $user = require_user($pdo);
        $sql = 'SELECT application_code AS id, child_name AS child, birth_date AS dob, '
            . 'place_of_birth AS pob, parent_name AS parent, parent_national_id AS nid, '
            . 'parent_phone AS phone, status, DATE_FORMAT(created_at, "%d/%m/%Y") AS date '
            . 'FROM applications';
        if ($user['role'] === 'applicant') {
            $stmt = $pdo->prepare($sql . ' WHERE applicant_id = ? ORDER BY id DESC');
            $stmt->execute([$user['id']]);
            respond(['applications' => $stmt->fetchAll()]);
        }
        respond(['applications' => $pdo->query($sql . ' ORDER BY id DESC')->fetchAll()]);
    }

    if ($action === 'applications' && $method === 'POST') {
        require_csrf();
        $user = require_user($pdo, 'applicant');
        $data = request_data();
        $fields = [
            'child' => trim((string)($data['child'] ?? '')),
            'dob' => trim((string)($data['dob'] ?? '')),
            'pob' => trim((string)($data['pob'] ?? '')),
            'parent' => trim((string)($data['parent'] ?? '')),
            'nid' => trim((string)($data['nid'] ?? '')),
            'phone' => trim((string)($data['phone'] ?? '')),
        ];
        foreach ($fields as $value) {
            if ($value === '') {
                respond(['error' => 'Complete all application fields.'], 400);
            }
        }
        $date = DateTime::createFromFormat('!Y-m-d', $fields['dob']);
        if (!$date || $date->format('Y-m-d') !== $fields['dob']) {
            respond(['error' => 'Enter a valid date of birth.'], 400);
        }
        $duplicateKey = hash('sha256', strtolower($fields['child']) . "\0" . $fields['dob'] . "\0" . strtolower($fields['nid']));
        try {
            $stmt = $pdo->prepare(
                'INSERT INTO applications (child_name, birth_date, place_of_birth, parent_name, '
                . 'parent_national_id, parent_phone, applicant_id, duplicate_key) VALUES (?, ?, ?, ?, ?, ?, ?, ?)'
            );
            $stmt->execute([
                $fields['child'], $fields['dob'], $fields['pob'], $fields['parent'],
                $fields['nid'], $fields['phone'], $user['id'], $duplicateKey,
            ]);
        } catch (PDOException $error) {
            if ($error->getCode() === '23000') {
                $stmt = $pdo->prepare('SELECT application_code FROM applications WHERE duplicate_key = ?');
                $stmt->execute([$duplicateKey]);
                $existing = $stmt->fetchColumn();
                $message = $existing
                    ? 'Duplicate blocked: this child is already registered under Application ID ' . $existing . '.'
                    : 'A matching application has already been submitted.';
                respond(['error' => $message], 409);
            }
            throw $error;
        }
        $id = (int)$pdo->lastInsertId();
        $code = 'BT' . str_pad((string)$id, 4, '0', STR_PAD_LEFT);
        $stmt = $pdo->prepare('UPDATE applications SET application_code = ? WHERE id = ?');
        $stmt->execute([$code, $id]);
        respond(['id' => $code], 201);
    }

    if ($action === 'applications' && $method === 'PATCH') {
        require_csrf();
        require_user($pdo, 'clerk');
        $id = trim((string)($_GET['id'] ?? ''));
        $status = (string)(request_data()['status'] ?? '');
        $stages = ['Submitted', 'Under Review', 'Approved', 'Issued'];
        if ($id === '' || !in_array($status, $stages, true)) {
            respond(['error' => 'Choose a valid application and status.'], 400);
        }
        $stmt = $pdo->prepare('UPDATE applications SET status = ? WHERE application_code = ?');
        $stmt->execute([$status, $id]);
        if ($stmt->rowCount() === 0) {
            $stmt = $pdo->prepare('SELECT 1 FROM applications WHERE application_code = ?');
            $stmt->execute([$id]);
            if (!$stmt->fetchColumn()) {
                respond(['error' => 'That application no longer exists.'], 404);
            }
        }
        respond(['ok' => true]);
    }

    respond(['error' => 'Unknown action or unsupported method.'], 404);
} catch (PDOException $error) {
    error_log('BirthTrack database error: ' . $error->getMessage());
    respond(['error' => 'Database unavailable. Start MySQL in XAMPP and import database.sql if this is a new installation.'], 500);
}
