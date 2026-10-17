<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store');
header('X-Content-Type-Options: nosniff');
header('Referrer-Policy: no-referrer');

if (empty($_SERVER['HTTPS']) || $_SERVER['HTTPS'] === 'off') {
    http_response_code(403);
    echo json_encode(['error' => 'HTTPS obrigatório']);
    exit;
}
session_name('passkey_sid');
session_set_cookie_params(['lifetime' => 0, 'path' => '/', 'secure' => true, 'httponly' => true, 'samesite' => 'Strict']);
ini_set('session.use_strict_mode', '1');
session_start();

function fail(int $code, string $reason): never {
    http_response_code($code);
    echo json_encode(['error' => $reason], JSON_UNESCAPED_UNICODE);
    exit;
}
function reply(array $data): never {
    echo json_encode($data, JSON_UNESCAPED_UNICODE | JSON_THROW_ON_ERROR);
    exit;
}
function input(): array {
    $raw = file_get_contents('php://input', false, null, 0, 200000);
    if ($raw === false || strlen($raw) > 150000) fail(413, 'Solicitação grande demais');
    $data = json_decode($raw, true);
    if (!is_array($data)) fail(400, 'JSON inválido');
    return $data;
}
function ensureAuth(): void {
    if (empty($_SESSION['vault_auth'])) fail(401, 'Sessão expirada');
}
function checkCsrf(array $data): void {
    if (!hash_equals($_SESSION['csrf'] ?? '', (string)($data['csrf'] ?? ''))) fail(403, 'CSRF inválido');
    $origin = $_SERVER['HTTP_ORIGIN'] ?? '';
    $expected = 'https://' . ($_SERVER['HTTP_HOST'] ?? '');
    if ($origin !== '' && $origin !== $expected) fail(403, 'Origem inválida');
}
function validBlob(mixed $blob): bool {
    if (!is_string($blob) || strlen($blob) > 70000) return false;
    $data = json_decode($blob, true);
    return is_array($data) && ($data['v'] ?? null) === 1
        && is_string($data['iv'] ?? null) && strlen($data['iv']) === 16
        && base64_decode($data['iv'], true) !== false
        && strlen(base64_decode($data['iv'], true)) === 12
        && is_string($data['ct'] ?? null) && strlen($data['ct']) >= 24
        && base64_decode($data['ct'], true) !== false;
}
try {
    $configFile = dirname(__DIR__) . '/config.php';
    if (!is_file($configFile)) fail(503, 'Crie web/config.php a partir de config.example.php');
    $cfg = require $configFile;
    $db = new PDO(
        'mysql:host=' . $cfg['db_host'] . ';port=' . (int)$cfg['db_port'] . ';dbname=' . $cfg['db_name'] . ';charset=utf8mb4',
        $cfg['db_user'],
        $cfg['db_password'],
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION, PDO::ATTR_EMULATE_PREPARES => false]
    );
    $vault = $db->query('SELECT password_hash,kdf_salt,check_blob FROM web_vault WHERE id=1')->fetch(PDO::FETCH_ASSOC);
    $method = $_SERVER['REQUEST_METHOD'] ?? 'GET';
    $action = $_GET['action'] ?? '';
    if ($method === 'GET' && $action === 'state') {
        $_SESSION['csrf'] ??= bin2hex(random_bytes(32));
        reply([
            'configured' => $vault !== false,
            'authenticated' => !empty($_SESSION['vault_auth']),
            'salt' => $vault['kdf_salt'] ?? null,
            'check' => !empty($_SESSION['vault_auth']) ? $vault['check_blob'] : null,
            'csrf' => $_SESSION['csrf']
        ]);
    }
    if ($method !== 'POST') fail(405, 'Método não permitido');
    $body = input();
    checkCsrf($body);

    if ($action === 'setup') {
        if ($vault !== false) fail(409, 'Cofre já inicializado');
        $pass = $body['password'] ?? '';
        $salt = $body['salt'] ?? '';
        $check = $body['check'] ?? null;
        if (!is_string($pass) || strlen($pass) < 16 || strlen($pass) > 1024
            || !is_string($salt) || !preg_match('/^[a-f0-9]{32}$/', $salt)
            || !validBlob($check)) fail(422, 'Parâmetros inválidos');
        $hash = password_hash($pass, PASSWORD_ARGON2ID);
        $q = $db->prepare('INSERT INTO web_vault (id,password_hash,kdf_salt,check_blob) VALUES (1,?,?,?)');
        $q->execute([$hash, $salt, $check]);
        session_regenerate_id(true);
        $_SESSION['vault_auth'] = true;
        reply(['ok' => true]);
    }
    if ($action === 'login') {
        if ($vault === false) fail(409, 'Cofre não configurado');
        if (($_SESSION['blocked_until'] ?? 0) > time()) fail(429, 'Aguarde antes de tentar novamente');
        $pass = $body['password'] ?? '';
        if (!is_string($pass) || !password_verify($pass, $vault['password_hash'])) {
            $_SESSION['fails'] = ($_SESSION['fails'] ?? 0) + 1;
            if ($_SESSION['fails'] >= 5) $_SESSION['blocked_until'] = time() + 300;
            fail(401, 'Senha incorreta');
        }
        unset($_SESSION['fails'], $_SESSION['blocked_until']);
        session_regenerate_id(true);
        $_SESSION['vault_auth'] = true;
        reply(['ok' => true, 'check' => $vault['check_blob']]);
    }
    if ($action === 'logout') {
        $_SESSION = [];
        session_destroy();
        reply(['ok' => true]);
    }
    ensureAuth();
    if ($action === 'list') {
        $entries = $db->query('SELECT id,payload FROM web_entries ORDER BY id DESC')->fetchAll(PDO::FETCH_ASSOC);
        reply(['entries' => $entries]);
    }
    if ($action === 'save') {
        $blob = $body['payload'] ?? null;
        if (!validBlob($blob)) fail(422, 'Registro criptografado inválido');
        $id = $body['id'] ?? null;
        if ($id === null) {
            $q = $db->prepare('INSERT INTO web_entries (payload) VALUES (?)');
            $q->execute([$blob]);
            reply(['ok' => true, 'id' => (int)$db->lastInsertId()]);
        }
        if (!is_int($id) || $id < 1) fail(422, 'ID inválido');
        $q = $db->prepare('UPDATE web_entries SET payload=? WHERE id=?');
        $q->execute([$blob, $id]);
        reply(['ok' => true]);
    }
    if ($action === 'delete') {
        $id = $body['id'] ?? null;
        if (!is_int($id) || $id < 1) fail(422, 'ID inválido');
        $q = $db->prepare('DELETE FROM web_entries WHERE id=?');
        $q->execute([$id]);
        reply(['ok' => true]);
    }
    fail(404, 'Ação não encontrada');
} catch (Throwable $e) {
    error_log('PassKey API error: ' . $e->getMessage());
    fail(500, 'Erro interno. Verifique o log PHP ou a configuração do banco');
}
