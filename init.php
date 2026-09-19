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
 * @copyright  2021-2021 CirkoTech
 * @license    http://www.php.net/license/3_01.txt  PHP License 3.01
 */

/**
 * Server initialization script
 * 
 * This file sets up the basic environment for the RADIUS server including:
 * - Defining base directory constants
 * - Setting up debug level constants
 * - Including configuration file
 * - Configuring autoloader for class loading
 * 
 * @package radius-server
 * @author Dragutin Cirkovic <dragonmen@gmail.com>
 */

// Set base directory constant for the server
const RADIUS_SERVER_BASE = __DIR__;

// Constants for debug levels
define("RADIUS_OFF", 0);
define("RADIUS_BASIC", 1);
define("RADIUS_CONNECTION", 2);
define("RADIUS_INFO", 3);
define("RADIUS_DEBUG", 4);

// Include the configuration file
require_once RADIUS_SERVER_BASE.DIRECTORY_SEPARATOR.'config.php';

// Set up autoloader for class loading
spl_autoload_register(function ($class_name) {
    $class_name = str_replace('\\',DIRECTORY_SEPARATOR,$class_name);	
    require_once RADIUS_SERVER_BASE . DIRECTORY_SEPARATOR . 'classes' . DIRECTORY_SEPARATOR . $class_name . '.php';
});
