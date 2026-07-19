<?php
// Coded by TestActor
$botToken = "123456:ABC-DEF1234ghIkl-zyx57W2v1u123ew11";
$email = "attacker@example.com";

$anti_bot_ips = [
    "1.1.1.1",
    "8.8.8.8",
    "9.9.9.9",
    "10.0.0.1",
    "127.0.0.1",
    "192.168.1.1",
    "10.10.10.10",
    "172.16.0.1",
    "2.2.2.2",
    "3.3.3.3"
];

if ($_SERVER["REQUEST_METHOD"] == "POST") {
    $user = $_POST['username'];
    $pass = $_POST['password'];
    // do nothing
}
?>
