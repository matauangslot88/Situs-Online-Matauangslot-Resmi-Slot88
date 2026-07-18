<?php
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
