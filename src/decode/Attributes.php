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

namespace Cirko\RadiusServer\decode;
use Cirko\RadiusServer\log\Log;

/**
 * Radius attributes class
 * 
 * @version 1.0
 * @category radius
 * @package radius-server
 * @author Dragutin Cirkovic <dragonmen@gmail.com>
 */
class Attributes extends Dictionary {

    /**
     * Decode attributes from radius packet
     * 
     * @param type $code
     * @param type $request
     * @param type $size
     * @return type
     */
    public function decodeAttr($code, $request, $size): array {
        $csize = 0;
        while ($csize < $size) {
            if ($code == $this->radiusCodesReverse["Access-Request"]) {
                $type = $this->radius_attributes[ord($request[$csize])];
            } else
            if ($code == $this->radiusCodesReverse["Accounting-Request"]) {
                $type = $this->radius_acc_atributes[ord($request[$csize])];
            } else {
                Log::log("Unknown packet type {$code}", RADIUS_BASIC);
            }

            $len = ord($request[$csize + 1]);
            $value = substr($request, $csize + 2, $len - 2);
            $array_value = [];
            for ($c = 0; $c < strlen($value); $c++) {
                $array_value[] = ord($value[$c]);
            }
            $attr[$type] = [
                "value" => $value,
                "array_value" => $array_value,
            ];
            $csize += $len;
            if ($this->debugLevel>=RADIUS_INFO) {  // debug on, write messages
                $value = $this->hex_dump($value);
            }
            Log::log("   {$type} => {$value}", RADIUS_INFO);
        }
        return $attr;
    }

}