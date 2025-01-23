<?php

declare(strict_types = 1);

/* vim: set expandtab tabstop=4 shiftwidth=4 softtabstop=4: */
/**
 * LICENSE: This source file is subject to version 3.01 of the PHP license
 * that is available through the world-wide-web at the following URI:
 * http://www.php.net/license/3_01.txt.  If you did not receive a copy of
 * the PHP License and are unable to obtain it through the web, please
 * send a note to license@php.net so we can mail you a copy immediately.
 *
 * @author     Dragutin Cirkovic <dragonmen@gmail.com>
 * @copyright  2021-2025 CirkoTech
 * @license    http://www.php.net/license/3_01.txt  PHP License 3.01
 */

namespace Cirko\RadiusServer\log;

/**
 * Radius Log class
 * 
 * @version 1.0
 * @category radius
 * @package radius-server
 * @author Dragutin Cirkovic <dragonmen@gmail.com>
 */
class Log{

    private static $debugLevel;
    private static $log_file;

    /**
     * Log message to either file or screen, depending on settings
     * 
     * @param string $message Message to log/show
     * @param int    $debug Debug to match this message
     */
    public static function log($message, $debug = NULL) {
        if ($debug === NULL || self::$debugLevel >= $debug) {  // debug on, write messages
            if (self::$log_file) {  // log file defined?
                $r = file_put_contents(self::$log_file, $message, FILE_APPEND); // add to log
                if ($r === FALSE) { // write to log failed?
                    echo "ERROR: Could not write to log!\n";
                }
            } else {
                echo $message . "\n";   // echo to console
            }
        }
    }

    public static function setDebugLevel($level):void {
        self::$debugLevel=$level;
    }
    
    public static function setFile($file):void {
        self::$log_file=$file;
    }
}