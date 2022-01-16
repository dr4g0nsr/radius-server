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

namespace auth;

/**
 * File based authentication class
 *
 * Example class how you can use simple file checking for authentication
 *
 * @category   Boilerplate
 * @package    Lumen-Boilerplate
 * @version    Release: @package_version@
 * @link       http://pear.php.net/package/Lumen-Boilerplate
 * @see        NetOther, Net_Sample::Net_Sample()
 * @since      Class available since Release 1.2.0
 * @deprecated Class deprecated in Release 2.0.0
 */
class File {

    public function getLoginInfo(string $username) {
        if ($username == 'username') {
            return [
                'password' => "password",
                'Framed-IP-Address' => '1.1.2.2',
                'Framed-Protocol' => 'PPP',
                'Service-Type' => 'Framed-User',
                'Framed-Pool' => 'pppoe-pool-1',
                'Session-Timeout' => 324532,
            ];
        }
    }

}
