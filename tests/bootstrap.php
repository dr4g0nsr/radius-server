<?php

// Bootstrap file for tests
require_once __DIR__ . '/../vendor/autoload.php';

// Set up basic test environment
define('RADIUS_SERVER_BASE', __DIR__ . '/..');
define('RADIUS_BASIC', 1);
define('RADIUS_CONNECTION', 2);
define('RADIUS_INFO', 3);
define('RADIUS_DEBUG', 4);

// Ensure directory structure exists for tests
if (!is_dir(__DIR__ . '/../classes/server/base')) {
    mkdir(__DIR__ . '/../classes/server/base', 0755, true);
}