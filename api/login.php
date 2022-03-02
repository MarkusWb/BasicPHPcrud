<?php
require 'config.php';
require_once __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

header('Content-Type: application/json');

try {
  $content = file_get_contents('php://input');
  $credentials = json_decode($content, true);
  $roles = auth_or_exit($credentials, $host_name, $user_name, $password, $database, $user_meta);
} catch (Exception $ex) {
  exit_msg_code('Malformed request', 400);
}

$issuedAt   = new DateTimeImmutable();
$validity   = '+360 minutes';
$expires    = $issuedAt->modify($validity);
$serverName = $_SERVER['HTTP_HOST'];
$username   = $credentials['user'];

$payload = [
    'iat'  => $issuedAt->getTimestamp(),
    'iss'  => $serverName,
    'aud'  => $serverName,
    'nbf'  => $issuedAt->getTimestamp(),
    'exp'  => $expires->getTimestamp(),
    'userName' => $username,
    'roles' => $roles
];

$jwt = JWT::encode($payload, $jwt_key, 'HS256');

$resp = [
    'userName' => $payload['userName'],
    'roles'    => $payload['roles'],
    'jwt'      => $jwt,
    'expires'  => $expires->format('c')
];

echo json_encode($resp);

function auth_or_exit($credentials, $host_name, $user_name, $password, $database, $user_meta) {
  if (!$credentials || !isset($credentials['user']) || !isset($credentials['password'])) {
    if (isset($credentials['to_hash'])) {
      echo '{"hash": "' . password_hash($credentials['to_hash'], PASSWORD_DEFAULT) . '"}';
      exit;
    }
    
    $user = load_user($credentials, $host_name, $user_name, $password, $database, $user_meta);
        
    if (isset($credentials['reset'])) {
      // create refresh code with expiration in database, send to mail
      // expects user and reset
      $expires = (new DateTimeImmutable())->modify('+30 minutes');
      $params = [
              $expires->getTimestamp() . '-' . uniqid(rand(), true),
              $user['id']
      ];
      $sql = 'UPDATE ' . $user_meta['t_users'] . ' SET '. $user_meta['f_reset'] . '=? WHERE id=?';
      run_sql_statement('POST', $host_name, $user_name, $password, $database, $sql, $params);
    }
    if (isset($credentials['reset_code'])) {
      // check refresh code and expiration
      // expects user, reset_code, and new_password
    }
    exit_msg_code('Missing credentials', 401);
  }
  $user = load_user($credentials, $host_name, $user_name, $password, $database, $user_meta);
  $hash = $user[0][$user_meta['f_hash']];
  if (!password_verify($credentials['password'], $hash))
  {
    exit_msg_code('Wrong credentials', 401);
  }
  if (isset($credentials['new_password'])) {
    // set new password
  }
  return $hash = $user[0]['roles'];
}
?>
