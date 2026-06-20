<?php
declare(strict_types=1);

header('Content-Type: application/json; charset=utf-8');
header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');

const DATA_FILE = __DIR__ . '/data.json';
const MIN_TOKEN_LENGTH = 64;

$secret = getenv('DV2_SHARED_SECRET') ?: 'CHANGE_ME_SHARED_SECRET_64_CHARS_MINIMUM_DO_NOT_COMMIT_REAL_SECRET';
$provided = $_SERVER['HTTP_X_AUTH_TOKEN'] ?? '';

if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    echo json_encode(['ok' => false, 'error' => 'Nur POST erlaubt.']);
    exit;
}

if (!is_string($provided) || !hash_equals($secret, $provided)) {
    http_response_code(403);
    echo json_encode(['ok' => false, 'error' => 'Ungültiges Shared Secret.']);
    exit;
}

$raw = file_get_contents('php://input');
if ($raw === false || strlen($raw) > 1024 * 1024) {
    http_response_code(400);
    echo json_encode(['ok' => false, 'error' => 'Ungültiger Request.']);
    exit;
}

$payload = json_decode($raw, true, flags: JSON_THROW_ON_ERROR);
$token = $payload['token'] ?? '';
if (!is_string($token) || strlen($token) < MIN_TOKEN_LENGTH || !preg_match('/^[A-Za-z0-9+\/=._:-]+$/', $token)) {
    http_response_code(422);
    echo json_encode(['ok' => false, 'error' => 'Token fehlt oder ist zu kurz.']);
    exit;
}

$out = json_encode([
    'token' => $token,
    'updated' => gmdate('c'),
], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR);

$tmp = DATA_FILE . '.tmp';
if (file_put_contents($tmp, $out, LOCK_EX) === false || !rename($tmp, DATA_FILE)) {
    @unlink($tmp);
    http_response_code(500);
    echo json_encode(['ok' => false, 'error' => 'data.json konnte nicht geschrieben werden.']);
    exit;
}

http_response_code(200);
echo json_encode(['ok' => true, 'updated' => gmdate('c')]);
