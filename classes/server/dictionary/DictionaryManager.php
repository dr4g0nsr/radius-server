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

namespace server\dictionary;

/**
 * Dictionary manager for RADIUS server
 * 
 * This class handles loading and management of RADIUS dictionary files,
 * which contain attribute definitions and vendor mappings.
 * 
 * @version 1.0
 * @category radius
 * @package radius-server
 * @author Dragutin Cirkovic <dragonmen@gmail.com>
 */
class DictionaryManager {

    /**
     * Standard RADIUS attributes mapping
     * @var array
     */
    public $radius_attributes = [
        1 => "User-Name",
        2 => "User-Password",
        3 => "CHAP-Password",
        4 => "NAS-IP-Address",
        5 => "NAS-Port",
        6 => "Service-Type",
        7 => "Framed-Protocol",
        8 => "Framed-IP-Address",
        9 => "Framed-IP-Netmask",
        10 => "Framed-Routing",
        11 => "Filter-ID",
        12 => "Framed-MTU",
        13 => "Framed-Compression",
        14 => "Login-IP-Host",
        15 => "Login-Service",
        16 => "Login-TCP-Port",
        18 => "Reply-Message",
        19 => "Callback-Number",
        20 => "Callback-Id",
        24 => "State",
        25 => "Class",
        26 => "Vendor-Specific",
        27 => "Session-Timeout",
        28 => "Idle-Timeout",
        29 => "Termination-Action",
        30 => "Called-Station-Id",
        31 => "Calling-Station-Id",
        32 => "NAS-Identifier",
        33 => "Proxy-State",
        34 => "Login-LAT-Service",
        35 => "Login-LAT-Node 3",
        36 => "Login-LAT-Group",
        37 => "Framed-AppleTalk-Link",
        38 => "Framed-AppleTalk-Network",
        39 => "Framed-AppleTalk-Zone",
        60 => "CHAP-Challenge",
        61 => "NAS-Port-Type",
        62 => "Port-Limit",
        63 => "Login-LAT-Port",
        79 => "EAP-Message",
        80 => "Message-Authenticator",
        87 => "NAS-Port-ID",
    ];
    
    /**
     * Accounting attributes mapping
     * @var array
     */
    public $radius_acc_atributes = [
        40 => "Acct-Status-Type",
        41 => "Acct-Delay-Time",
        42 => "Acct-Input-Octets",
        43 => "Acct-Output-Octets",
        44 => "Acct-Session-Id",
        45 => "Acct-Authentic",
        46 => "Acct-Session-Time",
        47 => "Acct-Input-Packets",
        48 => "Acct-Output-Packets",
        49 => "Acct-Terminate-Cause",
        50 => "Acct-Multi-Session-Id",
        51 => "Acct-Link-Count",
    ];
    
    /**
     * RADIUS packet codes mapping
     * @var array
     */
    public $radius_codes = [
        1 => "Access-Request",
        2 => "Access-Accept",
        3 => "Access-Reject",
        4 => "Accounting-Request",
        5 => "Accounting-Response",
        11 => "Access-Challenge",
        12 => "Status-Server",
        13 => "Status-Client",
    ];
    
    /**
     * Reverse mapping for attributes (attribute ID to name)
     * @var array
     */
    public $radiusAttributesReverse = [];
    
    /**
     * Vendor-specific attributes
     * @var array
     */
    public $vendorRadiusAttributes = [];
    
    /**
     * Reverse mapping for vendor attributes
     * @var array
     */
    public $vendorRadiusAttributesReverse = [];
    
    /**
     * Reverse mapping for codes
     * @var array
     */
    public $radiusCodesReverse = [];

    /**
     * Load dictionaries
     * 
     * @param string $file Filename that will be load as root, default to dictionary
     * @return bool Return true on loaded file, otherwise false
     */
    public function load_dictionary(string $file = "dictionary"): bool {
        $dictionaryPath = RADIUS_SERVER_BASE . DIRECTORY_SEPARATOR . "dictionary" . DIRECTORY_SEPARATOR . $file;
        if (file_exists($dictionaryPath)) {
            $this->log("Load " . $file, RADIUS_BASIC);
            $dict = file_get_contents(RADIUS_SERVER_BASE . "/dictionary/" . $file);
            $dict_lines = explode("\n", $dict);
            $current_vendor = null;
            foreach ($dict_lines as $dict_item) {
                if (strlen($dict_item) < 10 || $dict_item[0] == "#") {
                    continue;
                } else
                if (substr($dict_item, 0, 8) == "\$INCLUDE") {
                    $dict_file = trim(substr($dict_item, 9));
                    $this->load_dictionary($dict_file);
                } else {
                    $dict_item = str_replace(chr(9), " ", $dict_item);  // convert tab to space
                    while (strpos($dict_item, "  ")) {  // remove double spaces
                        $dict_item = str_replace("  ", " ", $dict_item);
                    }
                    $dict_item_e = explode(" ", $dict_item);    // split by space
                    switch ($dict_item_e[0]) {
                        case "VENDOR":
                            $this->vendorRadiusAttributes[$dict_item_e[1]]["id"] = $dict_item_e[2];
                            break;
                        case "BEGIN-VENDOR":
                            $current_vendor = $dict_item_e[1];
                            break;
                        case "END-VENDOR":
                            $current_vendor = null;
                            break;
                        case "ATTRIBUTE":
                            if (!$current_vendor) {
                                $this->radius_attributes[$dict_item_e[2]] = $dict_item_e[1];
                            } else {
                                $this->vendorRadiusAttributes[$current_vendor][$dict_item_e[1]] = $dict_item_e[2];
                            }
                            break;
                        case "VALUE":
                            break;
                        default:
                    }
                }
            }
            return true;
        } else {
            $this->log("Failed to load " . $file, RADIUS_BASIC);
            return false;
        }
    }

    /**
     * Reverse lookup dictionary
     * 
     * Used to parse format from dictionary where is stored in val - key order
     * 
     * @return void
     */
    public function reverse_dictionary(): void {
        $this->radiusAttributesReverse = array_flip($this->radius_attributes);    // much faster to lookup for reverse attr
        $this->radiusCodesReverse = array_flip($this->radius_codes);  // much faster to lookup for reverse codes
        $this->setup_attributes($this->vendorRadiusAttributes);
    }

    /**
     * Just iterate and inverse to property
     * 
     * @param array $attrs Attribute to inverse
     * 
     * @return void
     */
    private function inverseAttributes(array $attrs): void {
        foreach ($attrs as $id => $val) {
            $this->vendorRadiusAttributesReverse[$id] = $val;
        }
    }

    /**
     * Iterate all found attributes and store it into var
     * 
     * @param array $vendor_radius_attributes Attributes read from dictionary files
     * 
     * @return void
     */
    private function setup_attributes(array $vendor_radius_attributes): void {
        foreach ($this->vendorRadiusAttributes as $attr => $vars) {
            if (isset($vars["id"])) {
                $this->vendorRadiusAttributesReverse[$vars["id"]] = $vars;
                continue;
            }
            if (is_array($vars)) {
                $this->inverseAttributes($vars);
                continue;
            }
        }
    }

    /**
     * Log message to either file or screen, depending on settings
     * 
     * @param string $message Message to log/show
     * @param int|null $debug Debug level to match this message (optional)
     * 
     * @return void
     */
    protected function log(string $message, ?int $debug = null): void {
        // This is a placeholder - actual logging would be handled by parent class
        if ($debug === null || $debug >= RADIUS_BASIC) {  // debug on, write messages
            echo $message . "\n";   // echo to console
        }
    }

}