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

namespace server\attribute;

/**
 * Attribute handler for RADIUS server
 * 
 * This class handles the encoding and decoding of RADIUS attributes,
 * including vendor-specific attributes.
 * 
 * @version 1.0
 * @category radius
 * @package radius-server
 * @author Dragutin Cirkovic <dragonmen@gmail.com>
 */
class AttributeHandler {

    /**
     * Sets the attribute
     * 
     * @param string $attribute Attribute name
     * @param string $value Value to set
     * @param array $radiusAttributesReverse Regular attributes mapping
     * @param array $vendorRadiusAttributes Vendor attributes mapping  
     * @return string|bool Packed attribute value or false on error
     */
    public function set_attribute(string $attribute, string $value, array $radiusAttributesReverse, array $vendorRadiusAttributes) {
        // Check for regular attributes first
        $code = @$radiusAttributesReverse[$attribute];
        if (!$code) {
            // Check for vendor attributes (Mikrotik, etc.)
            foreach ($vendorRadiusAttributes as $vendor => $attrs) {
                if (isset($attrs[$attribute])) {
                    // This is a vendor attribute - need to construct the proper format
                    // Vendor attributes are encoded as: [Vendor-Id][Attribute-Code][Length][Value]
                    // Where Vendor-Id is 4 bytes, Attribute-Code is 1 byte, Length is 1 byte, Value is the data
                    $vendor_id = $attrs["id"];
                    $attr_code = $attrs[$attribute];
                    $length = strlen($value) + 2; // +2 for code and length bytes
                    $packed = pack("CCCCa" . strlen($value), 
                        ($vendor_id >> 24) & 0xFF, 
                        ($vendor_id >> 16) & 0xFF, 
                        ($vendor_id >> 8) & 0xFF, 
                        $vendor_id & 0xFF,
                        $attr_code,
                        $length,
                        $value
                    );
                    return $packed;
                }
            }
            // If we get here, the attribute is unknown
            return false;
        }

        $packed = pack("CCa" . strlen($value), $code, strlen($value) + 2, $value);
        return $packed;
    }

}