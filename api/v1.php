<?php
require 'config.php';
require_once __DIR__ . '/vendor/autoload.php';

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

header('Content-Type: application/json');

if (!isset($_SERVER[$path_info]) || $_SERVER[$path_info] === '/' || $_SERVER[$path_info] === $_SERVER['PHP_SELF']) {
  exit_msg_code('Path undefined', 400);
}

if (!isset($_SERVER[$auth_header_field])) {
  exit_msg_code('Missing authorization', 401);
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
  $exploded = explode(':', base64_decode(substr($_SERVER[$auth_header_field], 6)), 2);
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
$path = explode("/", substr(@$_SERVER[$path_info], 1));
$query_parameters = get_query_parameters(explode("&", $_SERVER['QUERY_STRING']));


filter_by_role($token, /*$user,*/ $path, $auth_filter);


// basic sanitation of table name
if (str_contains($path[0], ';') || str_contains($path[0], ' ')) {
  exit_msg_code('Path does not exist', 400);
}

try {
  switch ($method) {
    case 'GET':
      get($path, $query_parameters, $host_name, $user_name, $password, $database, $user_meta);
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


function get_query_parameters($param_strings) {
  $parameters = array();
  foreach ($param_strings as $param_string) {
    $part = explode('=', $param_string);
    $parameters[$part[0]] = sizeof($part) > 1 ? urldecode($part[1]) : "";
  }
  return $parameters;
}

function filter_by_role($token, /*$user,*/ $path, $auth_filter) {
  $user_roles = explode(",", $token['roles']); // for Basic auth use $user[0]['roles'] instead of $token['roles']
  if (isset($auth_filter[$path[0]]) && empty(array_intersect($auth_filter[$path[0]], $user_roles))) {
    exit_msg_code('Forbidden', 403);
  }
}

function get($path, $query_params, $host_name, $user_name, $password, $database, $u) {
  $single = isset($path[1]) && $path[1] !== '';
  
  $expands = join_info($path, $query_params, $host_name, $user_name, $password, $database);
  
  $query = 'SELECT '
        . main_table_fields($path, $u, $expands)   // restrict user table
        . $expands['selects']
        . ' FROM ' . $path[0] . ' e'
        . $expands['joins']
        . ($single ? ' WHERE e.id=?' : '');
  $parameters = $single ? [ $path[1] ] : [];
  
  $data = run_sql_statement('GET', $host_name, $user_name, $password, $database, $query, $parameters);
  if (!empty($expands['expands'])) {
    $data = expands_to_field($data, $expands);
  }
  if ($single) {
    $data = $data[0];
  }
  echo json_encode($data);
}

function main_table_fields($path, $u, $expands) {
  return $path[0] === $u['t_users']
      ? implode(', ', array_map(function($f) {return 'e.'.$f;}, explode(',', $u['allowed_fields'])))
      : 'e.*';
}

function join_info($path, $query_params, $host_name, $user_name, $password, $database) {
  $join = '';
  $selects = '';
  $expands = [];
  $cols = [];
  if (isset($query_params['$expand'])) {
    $sql_tables = 'SELECT TABLE_NAME FROM information_schema.tables WHERE table_type = "BASE TABLE"';
    $tables = array_map(function($t) {return $t['TABLE_NAME'];}, 
              run_sql_statement('GET', $host_name, $user_name, $password, $database, $sql_tables, [])
    );
    $tables_to_expand = explode(',', $query_params['$expand']);
    $c = 0;
    foreach ($tables_to_expand as $t_expand) {
      $t_manytomany = $path[0] . '_' . $t_expand;
      $join_available = FALSE;
      if (in_array($t_manytomany, $tables)) {
        $join .= ' INNER JOIN ' . $t_manytomany . ' mtm' . $c . 'ON e.id = mtm' . $c . '.' . $path[0] . '_id' .
                ' INNER JOIN ' . $t_expand . ' e' . $c . 'ON mtm.' . $t_expand . '_id = e' . $c . '.id';
        $join_available = TRUE;
      } elseif (in_array($t_expand, $tables)) {
        $join .= ' INNER JOIN ' . $t_expand . ' e' . $c . ' ON e.id = e' . $c . '.' . $path[0] . '_id';
        $join_available = TRUE;
      }
      if ($join_available) {
        $expands[] = $t_expand;
        $sql_columns = 'SHOW COLUMNS FROM ' . $t_expand;
        $cols = array_map(function($tc) {return $tc['Field'];}, 
                run_sql_statement('GET', $host_name, $user_name, $password, $database, $sql_columns, [])
        );
        $t_expand_fields = [];
        foreach ($cols as $col) {
          $new_colname = $t_expand . '_' . $col;
          $cols[$new_colname] = [ 'table' => $t_expand, 'col' => $col];
          $t_expand_fields[] = 'e' . $c . '.' . $col . ' AS ' . $new_colname;
        }
        $selects .= ', ' . implode(', ', $t_expand_fields);
      }
      $c++;
    }
  }
  return array( 'joins' => $join, 'selects' => $selects, 'expands' => $expands, 'cols' => $cols);
}

function expands_to_field($data, $expands) {
  $new_data = [];
  $sub_fields = [];
  foreach ($expands['expands'] as $table) {
    $sub_fields[$table] = [];
  }
  foreach ($data as $row) {
    $id = $row['id'];
    $main = [];
    foreach ($row as $col=>$val) {
      if (isset($expands['cols'][$col])) {
        $sub_fields[$expands['cols'][$col]['table']][$expands['cols'][$col]['col']] = $val;
      } else {
        $main[$col] = $val;
      }
    }
    if (!isset($new_data[$id])) {
      foreach ($expands['expands'] as $table) {
        $main[$table] = [];
      }
      $new_data[$id] = $main;
    }
    foreach ($sub_fields as $key=>$val) {
      $new_data[$id][$key][] = $val;
    }
  }
  return array_values($new_data);
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