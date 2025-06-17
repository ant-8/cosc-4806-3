<?php

class User {

  public $username;
  public $password;
  public $auth = false;

  public function __construct() {
        
  }

  public function test () {
    $db = db_connect();
    $statement = $db->prepare("select * from users;");
    $statement->execute();
    $rows = $statement->fetch(PDO::FETCH_ASSOC);
    return $rows;
  }

  public function authenticate($username, $password) {
    /*
     * if username and password good then
     * $this->auth = true;
    */
	$username = strtolower($username);
	$db = db_connect();
    $statement = $db->prepare("select * from users WHERE username = :name;");
    $statement->bindValue(':name', $username);
    $statement->execute();
    $rows = $statement->fetch(PDO::FETCH_ASSOC);

	if (password_verify($password, $rows['password'])) {
        $_SESSION['auth'] = 1;
		$_SESSION['username'] = ucwords($username);
		unset($_SESSION['failedAuth']);
		header('Location: /home');

	} else {
		if(isset($_SESSION['failedAuth'])) {
			$_SESSION['failedAuth'] ++; //increment
		} else {
			$_SESSION['failedAuth'] = 1;
		}
		header('Location: /login');

	}
  }

  public function username_exists($username) {
      $db = db_connect();
      $statement = $db->prepare("SELECT * FROM users WHERE username = :username");
      $statement->execute([':username' => $username]);
      return $statement->fetch(PDO::FETCH_ASSOC) !== false;
  }

  public function create_user($username, $password) {
      if ($this->username_exists($username)) {
          return ['success' => false, 'message' => 'Username already exists.'];
      }

      if (!$this->is_password_strong($password)) {
          return ['success' => false, 'message' => 'Password does not meet requirements.'];
      }

      $hashed_password = password_hash($password, PASSWORD_DEFAULT);

      $db = db_connect();
      $statement = $db->prepare("INSERT INTO users (username, password) VALUES (:username, :password)");
      $success = $statement->execute([
          ':username' => $username,
          ':password' => $hashed_password
      ]);

      return ['success' => $success, 'message' => $success ? 'Account created successfully' : 'Failed to create account.'];
  }

  private function is_password_strong($password) {
      return strlen($password) >= 8 &&
             preg_match('/[A-Z]/', $password) &&
             preg_match('/[a-z]/', $password) &&
             preg_match('/[0-9]/', $password) &&
             preg_match('/[\W]/', $password);
  }
}
