<?php

declare(strict_types=1);

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

namespace Cirko\RadiusServer\decode;

use Cirko\RadiusServer\log\Log;

/**
 * Radius dictionary class
 * 
 * @version 1.0
 * @category radius
 * @package radius-server
 * @author Dragutin Cirkovic <dragonmen@gmail.com>
 */
class Dictionary extends Codes
{
    public $debugLevel;

    /**
     * Iterate all found attributes and store it into var
     * 
     * @param array $vendor_radius_attributes Attributes read from dictionary files
     */
    protected function setup_attributes($vendor_radius_attributes) {
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
        if (DEBUG) {
            file_put_contents(__DIR__ . "/../../dump_attrs.txt", json_encode($this->vendorRadiusAttributesReverse), FILE_APPEND);
        }
    }

    /**
     * Reverse lookup dictionary
     * 
     * Used to parse format from dictionary where is stored in val - key order
     */
    public function reverse_dictionary()
    {
        $this->radiusAttributesReverse = array_flip($this->radius_attributes);    // much faster to lookup for reverse attr
        $this->radiusCodesReverse = array_flip($this->radius_codes);  // much faster to lookup for reverse codes
        $this->setup_attributes($this->vendorRadiusAttributes);
    }

    /**
     * Load dictionaries
     * 
     * @param string $file Filename that will be load as root, default to dictionary
     * @return boolean Return true on loaded file, otherwise false
     */
    public function load_dictionary($file = "dictionary"): bool
    {
        $dictionaryPath = RADIUS_SERVER_BASE . DIRECTORY_SEPARATOR . "dictionary" . DIRECTORY_SEPARATOR . $file;
        if (file_exists($dictionaryPath)) {
            Log::log("Load " . $file, RADIUS_BASIC);
            $dict = file_get_contents(RADIUS_SERVER_BASE . "/dictionary/" . $file);
            $dict_lines = explode("\n", $dict);
            $current_vendor = NULL;
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
                            $current_vendor = NULL;
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
            Log::log("Failed to load " . $file, RADIUS_BASIC);
            return false;
        }
    }
}
