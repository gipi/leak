<?php

session_start();

$table="users";

$dbms_host = '127.0.0.1';
$dbms_login = 'root';
$dbms_pass = 'password';
$dbms_dbname = 'sqli';

// create table users(id int(6) not null auto_increment PRIMARY KEY, login varchar(255), passwd varchar(255));
$db = new mysqli($dbms_host, $dbms_login, $dbms_pass, $dbms_dbname);
if ($db->connect_error) {
    die('Connect Error (' . $mysqli->connect_errno . ') '
        . $mysqli->connect_error);
}

function safe($string,$i=0) {
    $safe=strtolower($string);
    $safe = addslashes($safe);
    if ($i==1) $safe=htmlspecialchars($safe);
    return $safe;
}


$msg="";
if(isset($_POST['login'],$_POST['pass']) and !empty($_POST['login']) and !empty($_POST['pass']) ) {

    $passwd=sha1($_POST['pass'],true);
    $username=safe($_POST['login']);
    $sql="SELECT login FROM $table WHERE passwd='$passwd' AND login='$username'";
    if ($result = $db->query($sql)) {
        if($result->num_rows > 0){
                $_SESSION['logged']=1;
                header("Location: logged.php?user=$username");
        } else {
            $msg="no such user";
        }
        $result->close();
    } else {
      $msg = "SQL error : " . $db->error;
    }
}

$db->close();
?>
<form action="" method="POST">
    <input type="text" name="login">
    <input type="password" name="pass">
    <input type="submit">
</form>