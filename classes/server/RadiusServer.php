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

namespace server;

require_once __DIR__ . "/base/BaseRadiusServer.php";
require_once __DIR__ . "/dictionary/DictionaryManager.php";
require_once __DIR__ . "/attribute/AttributeHandler.php";

/**
 * RADIUS server class
 * 
 * This class implements a RADIUS server that handles authentication and accounting requests.
 * It supports various authentication methods and can be extended for custom implementations.
 * 
 * @version 1.0
 * @category radius
 * @package radius-server
 * @author Dragutin Cirkovic <dragonmen@gmail.com>
 */
class RadiusServer extends \server\base\BaseRadiusServer {
    
    /**
     * Dictionary manager instance
     * @var \server\dictionary\DictionaryManager
     */
    private $dictionaryManager;
    
    /**
     * Attribute handler instance
     * @var \server\attribute\AttributeHandler
     */
    private $attributeHandler;

    /**
     * Constructor - initializes the RADIUS server
     * 
     * @param string|null $serverip IP address to bind to (optional)
     * @param int|null $serverport Port number to listen on (optional)
     * 
     * @return void
     */
    public function __construct() {
        parent::__construct();
        
        // Initialize components
        $this->dictionaryManager = new \server\dictionary\DictionaryManager();
        $this->attributeHandler = new \server\attribute\AttributeHandler();
        
        // Load dictionaries
        $this->dictionaryManager->load_dictionary();
        $this->dictionaryManager->reverse_dictionary();
        
        // Copy the loaded attributes to the parent class properties for use in BaseRadiusServer methods
        if (isset($this->dictionaryManager->radius_attributes)) {
            $this->radius_attributes = $this->dictionaryManager->radius_attributes;
        }
        
        // Initialize radiusCodesReverse for use in BaseRadiusServer methods
        if (!isset($this->radiusCodesReverse) || empty($this->radiusCodesReverse)) {
            $this->radiusCodesReverse = array_flip($this->radius_codes);
        }
    }

    /**
     * Sets the attribute
     * 
     * @param string $attribute Attribute name
     * @param string $value Value to set
     * @return string|bool Packed attribute value or false on error
     */
    public function set_attribute(string $attribute, string $value) {
        $this->log("   {$attribute} -> {$value}", RADIUS_INFO);
        switch ($attribute) {
            case "Framed-IP-Address":
                $value = $this->encode_ip($value);
            default:
        }
        
        // Use the attribute handler to set the attribute
        return $this->attributeHandler->set_attribute(
            $attribute, 
            $value, 
            $this->dictionaryManager->radiusAttributesReverse,
            $this->dictionaryManager->vendorRadiusAttributes
        );
    }

    /**
     * Load dictionaries
     * 
     * @param string $file Filename that will be load as root, default to dictionary
     * @return bool Return true on loaded file, otherwise false
     */
    public function load_dictionary(string $file = "dictionary"): bool {
        return $this->dictionaryManager->load_dictionary($file);
    }

    /**
     * Reverse lookup dictionary
     * 
     * Used to parse format from dictionary where is stored in val - key order
     * 
     * @return void
     */
    public function reverse_dictionary(): void {
        $this->dictionaryManager->reverse_dictionary();
    }

}