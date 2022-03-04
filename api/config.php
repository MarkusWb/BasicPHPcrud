<?php
error_reporting(0);

$jwt_key  = 'someatleast256bitlongencryptionkey------------------------------';

// db infos
$host_name = 'dbhost.com';
$database = 'db12345';
$user_name = 'user12345';
$password = '12345';

$auth_header_field = 'REDIRECT_HTTP_AUTHORIZATION'; // could also be 'HTTP_AUTHORIZATION' depending on Apache settings
$path_info = 'ORIG_PATH_INFO';                      // could also be 'PATH_INFO' depending on Apache settings

$user_meta = [
    't_users' => 'users',
    't_roles' => 'userroles',
    't_join' => 'users_roles',
    'f_username' => 'username',
    'f_hash' => 'pwd_hash',
    'f_mail' => 'mail',
    'f_reset' => 'reset_code',
    'f_role' => 'role',
    'allowed_fields' => 'id,username'
];

$auth_filter = [
    'users' => array('admin')
];

function handle_db_error($link) {
  $msg = $link->error;
  $link->close();
  exit_msg_code($msg, 500);
}

function handle_statement_error($link, $statement) {
  $msg = $statement->error;
  $link->close();
  exit_msg_code($msg, 500);
}

function exit_msg_code($msg, $status) {
  http_response_code($status);
  exit('{"status": "failed", "message": "' . $msg . '"}');
}

function exit_on_bad_connection($link) {
  if ($link->connect_errno) {
    exit_msg_code($link->connect_error, 500);
  }
}

function load_user($credentials, $host_name, $user_name, $password, $database, $u) {
  $link = new mysqli($host_name, $user_name, $password, $database);
  exit_on_bad_connection($link);
  $query = 'SELECT u.id, u.' . $u['f_hash'] . ', u.' . $u['f_mail'] . ', u.' . $u['f_reset'] .
            ', group_concat(DISTINCT r.' . $u['f_role']. ' SEPARATOR ",") as roles' .
            ' FROM ' . $u['t_users'] . ' u' .
            ' INNER JOIN ' . $u['t_join'] . ' ur ON u.id = ur.' . $u['t_users'] . '_id' .
            ' INNER JOIN ' . $u['t_roles'] . ' r ON ur.' . $u['t_roles'] . '_id = r.id' .
            ' WHERE u.' . $u['f_username'] . ' = "' . $credentials['user'] . '"';  
  $result = $link->query($query);
  if (!$result) {
    echo 'ERROR ';
    handle_db_error($link);
  }
  $entry = $result->fetch_all(MYSQLI_ASSOC);
  //echo json_encode($entry);
  $link->close();
  
  return $entry;
}

function run_sql_statement($method, $host_name, $user_name, $password, $database, $sql, $parameters) {
  $link = new mysqli($host_name, $user_name, $password, $database);
  exit_on_bad_connection($link);
  
  $value = 0;
  
  $statement = $link->prepare($sql);
  if (!$statement) {
    handle_db_error($link);
  }
  $types = '';
  foreach ($parameters as $key => $value) {
    if (is_float($value)) {
      $types = $types . 'd';
    } elseif (is_int($value)) {
      $types = $types . 'i';
    } else {
      $types = $types . 's';
    }
  }
  if (!empty($parameters)) {
    if (!$statement->bind_param($types, ...$parameters)) {
      handle_statement_error($link, $statement);
    }
  }
  if (!$statement->execute()) {
    handle_statement_error($link, $statement);
  }
  $result = $statement->get_result();
  if (!$result && str_starts_with($method, 'GET')) {
    handle_statement_error($link, $statement);
  }
  if ($method === 'POST') {
    $value = $statement->insert_id;
  }
  if ($method === 'GET') {
    $value = $result->fetch_all(MYSQLI_ASSOC);
  }
  if ($method === 'DELETE') {
    if ($statement->affected_rows < 1) {
      exit_msg_code('Resource not found', 404);
    }
  }
  $link->close();
  return $value;
}
?>