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
 * @copyright  2021-2025 CirkoTech
 * @license    http://www.php.net/license/3_01.txt  PHP License 3.01
 */

namespace Cirko\RadiusServer\Auth;

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

    private $auth = [];
    private $loadedAt = NULL;
    private $loadEvery = 60;

    private function loadDB(): bool {
        $this->loadedAt = 0;
        $content = file_get_contents(RADIUS_SERVER_BASE . DIRECTORY_SEPARATOR . 'DB' . DIRECTORY_SEPARATOR . 'auth');
        if (!$content) {
            return false;
        }
        $contentNL = explode("\n", $content);

        $userName = '';
        foreach ($contentNL as $item) {
            if (empty($item) || $item[0] == '#') {
                continue;
            }
            if ($item[0] != ' ') {
                $userName = $item;
                continue;
            } else {
                $item = trim($item);
                $attr = explode("=", $item);
                $this->auth[$userName][trim($attr[0])] = trim($attr[1]);
            }
        }
        return true;
    }

    
    public function getLoginInfo(string $username):array|bool {
        // (Re)Loads auth db if empty or outdated
        if (empty($this->auth) || $this->loadedAt < microtime(true) - $this->loadEvery) {
            $this->loadDB();
        }
        if (!is_array($this->auth) || empty($this->auth) || !isset($this->auth[$username])) {
            return false;
        } else {
            return ($this->auth[$username]);
        }
    }

}
