<?php

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
/**
 * LICENSE: This source file is subject to version 3.01 of the PHP license
 * that is available through the world-wide-web at the following URI:
 * http://www.php.net/license/3_01.txt.  If you did not receive a copy of
 * the PHP License and are unable to obtain it through the web, please
 * send a note to license@php.net so we can mail you a copy immediately.
 *
 * @author     Dragutin Cirkovic <dragonmen@gmail.com>
 * @copyright  2021-2026 CirkoTech
 * @license    http://www.php.net/license/3_01.txt  PHP License 3.01
 */

/**
 * Main RADIUS server entry point
 * 
 * This file initializes and starts the RADIUS server with configured settings.
 * It loads the required classes, configures the server, and begins listening for
 * RADIUS authentication requests.
 * 
 * @package radius-server
 * @author Dragutin Cirkovic <dragonmen@gmail.com>
 */

// Include initialization script that sets up autoloading and constants
require_once __DIR__ . DIRECTORY_SEPARATOR . "init.php";

// Create new instance of the RADIUS server
$radius = new \server\RadiusServer();

// Configure debug level from config file
$radius->debugLevel = $config['debug'];

// Load all dictionary files for attribute definitions
$radius->load_dictionary();

// Initialize server with configuration settings
$radius->initialize();

// Start the main RADIUS server loop to handle incoming requests
$radius->radius_run($config);
