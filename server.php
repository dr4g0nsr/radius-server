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

require_once __DIR__ . DIRECTORY_SEPARATOR . "init.php";

$radius = new \server\RadiusServer;
$radius->debug_level = $config['debug'];
$radius->load_dictionary();
$radius->reverse_dictionary();
$radius->__init();
$radius->radius_run($config);
