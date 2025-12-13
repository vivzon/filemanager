<?php
session_start();

// 1. Security Check - No session required files
if (!isset($_SESSION['client_user']) && !isset($_SESSION['admin_user'])) {
    header("Location: /login.php");
    exit;
}

// 2. Define Root Path based on session
if (isset($_SESSION['admin_user'])) {
    $root_path = '/var/www/clients';
} else {
    $cuser = $_SESSION['client_user'];
    $root_path = "/var/www/clients/$cuser";
}

// 3. Ensure Directory Exists
if (!file_exists($root_path)) {
    mkdir($root_path, 0755, true);
}

// TEMP: show any PHP errors directly on the page while debugging.
// Remove or comment these three lines after it works.
ini_set('display_errors', 1);
ini_set('display_startup_errors', 1);
error_reporting(E_ALL);

require 'files_shm_view.php';

?>
