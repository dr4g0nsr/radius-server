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

    /**
     * Authentication data loaded from file
     * @var array
     */
    private $auth = [];
    
    /**
     * Time when auth data was last loaded
     * @var float|null
     */
    private $loadedAt = null;
    
    /**
     * How often to reload the auth database (in seconds)
     * @var int
     */
    private $loadEvery = 60;

    /**
     * Load authentication database from file
     * 
     * @return void
     */
    private function loadDB(): void {
        $this->loadedAt = 0;
        $content = file_get_contents(RADIUS_SERVER_BASE . DIRECTORY_SEPARATOR . 'DB' . DIRECTORY_SEPARATOR . 'auth');
        if (!$content) {
            return;
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
    }

    /**
     * Get login information for a user
     * 
     * @param string $username Username to look up
     * @return array|bool Login information if found, false otherwise
     */
    public function getLoginInfo(string $username) {
        // (Re)Loads auth db if empty or outdated
        if (empty($this->auth) || $this->loadedAt < microtime(true) - $this->loadEvery) {
            $this->loadDB();
        }
        return $this->auth[$username];
    }

}
