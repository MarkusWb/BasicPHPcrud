<?php
require 'config.php';
require_once __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

header('Content-Type: application/json');

if ($_SERVER['ORIG_PATH_INFO'] === '/' || $_SERVER['ORIG_PATH_INFO'] === $_SERVER['PHP_SELF']) {
  exit_msg_code('Path undefined', 400);
}


if (! preg_match('/Bearer\s(\S+)/', $_SERVER[$auth_header_field], $matches)) {
  exit_msg_code('Token not found in request', 401);
}

$jwt = $matches[1];
if (! $jwt) {
  exit_msg_code('Token could not be extracted', 401);
}

try {
  $token = (array) JWT::decode($jwt, new Key($jwt_key, 'HS256'));
} catch (Exception $jwt_ex) {
  exit_msg_code('Token invalid', 401);
}
$now = new DateTimeImmutable();
if ($token['iss'] !== $_SERVER['HTTP_HOST'] ||
    $token['nbf'] > $now->getTimestamp() ||
    $token['exp'] < $now->getTimestamp())
{
  exit_msg_code('Token invalid', 401);
}

/*
// Code for Basic Auth
if (isset($_SERVER[$auth_header_field]) && 0 === stripos($_SERVER[$auth_header_field], 'basic ')) {
  $exploded = explode(':', base64_decode(substr($_SERVER['REDIRECT_HTTP_AUTHORIZATION'], 6)), 2);
  if (2 == \count($exploded)) {
    list($req_user, $req_pw) = $exploded;
  }
  $user = load_user(array('user' => $req_user), $host_name, $user_name, $password, $database, $user_meta);
  if (!$user || !password_verify($req_pw, $user[0][$user_meta['f_hash']])) {
    exit_msg_code('Wrong credentials', 401);
  }
} else {
  header('WWW-Authenticate: Basic realm="test"');
  http_response_code(401);
  exit;
}
*/ 

$method = $_SERVER['REQUEST_METHOD'];
$path = explode("/", substr(@$_SERVER['ORIG_PATH_INFO'], 1));
$param_strings = explode("&", $_SERVER['argv'][0]);
$parameters = array();
foreach ($param_strings as $param_string) {
  $part = explode('=', $param_string);
  $parameters[$part[0]] = sizeof($part) > 1 ? urldecode($part[1]) : "";
}


$user_roles = explode(",", $token['roles']); // for Basic auth use $user[0]['roles'] instead of $token['roles']
if (isset($auth_filter[$path[0]]) && empty(array_intersect($auth_filter[$path[0]], $user_roles))) {
  exit_msg_code('Forbidden', 403);
}

// basic sanitation of table name
if (str_contains($path[0], ';') || str_contains($path[0], ' ')) {
  exit_msg_code('Path does not exist', 400);
}

try {
  switch ($method) {
    case 'GET':
      $single = isset($path[1]) && $path[1] !== '';
      $query = 'SELECT '
            . ($path[0] === $user_meta['t_users'] ? $user_meta['allowed_fields'] : '*')
            . ' FROM ' . $path[0] . ($single ? ' WHERE id=?' : '');
      $parameters = $single ? [ $path[1] ] : [];
      $data = run_sql_statement('GET' . ($single ? '' : '+'), $host_name, $user_name, $password, $database, $query, $parameters);
      echo json_encode($data);
      break;
    case 'POST':
      post_put($method, $path, file_get_contents('php://input'), $host_name, $user_name, $password, $database);
      break;
    case 'PUT':
      if (isset($path[1]) && $path[1] !== '') {
        post_put($method, $path, file_get_contents('php://input'), $host_name, $user_name, $password, $database);
      } else {
        exit_msg_code('Resource not defined', 400);
      }
      break;
    case 'DELETE':
      if (isset($path[1])) {
        $query = "DELETE FROM " . $path[0] . " WHERE id = ?";
        $data = run_sql_statement($method, $host_name, $user_name, $password, $database, $query, [ $path[1] ]);
        
        echo '{"status": "success", "message": "Deleted entry with id ' . $path[1] . ' from table ' . $path[0] . '"}';
        exit;
      } else {
        exit_msg_code('No resource defined', 400);
      }
      break;
    default:
      exit_msg_code('HTTP method not allowed', 405);
      break;
  }
} catch (Exception $ex) {
  exit_msg_code($ex->getMessage(), 500);
}

function post_put($method, $path, $content, $host_name, $user_name, $password, $database) {
  $obj = json_decode($content, true);
  $vals = $obj;
  
  $keys = [];
  $parameters = [];
  $placeholders = [];
  foreach ($vals as $key => $value) {
    if ($key !== 'id') {
      $keys[] = $key;
      $parameters[] = $value;
      $placeholders[] = '?';
    }
  }
  if ($method === 'POST') {
    $key_set = implode(',', $keys);
    $value_set = implode(',', $placeholders);
    $query = "INSERT INTO " . $path[0] . " (" . $key_set . ") VALUES (" . $value_set .")";
  } else {
    $parameters[] = $path[1];
    $pairs = implode(', ', array_map(function ($a) { return $a . '=?'; }, $keys));
    $query = "UPDATE " . $path[0] . " SET " . $pairs . " WHERE id = ?";
  }
  $data = run_sql_statement($method, $host_name, $user_name, $password, $database, $query, $parameters);
  if ($method === 'POST') {
    $obj['id'] = $data;
    http_response_code(201);
  }
  echo json_encode($obj);
}
?>