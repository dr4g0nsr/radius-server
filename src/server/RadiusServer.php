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

namespace Cirko\RadiusServer\server;

use Cirko\RadiusServer\decode\Attributes;
use Cirko\RadiusServer\log\Log;


/**
 * Radius server class
 * 
 * @version 1.0
 * @category radius
 * @package radius-server
 * @author Dragutin Cirkovic <dragonmen@gmail.com>
 */
class RadiusServer {

    private $attributes;
    public $debugLevel;
    private $serverip;
    private $serverport;
    private $socket;
    private $receive_buffer;
    private $secret;
    private $authMethod;
    private $time;

    private $requests;
    private $requests_min;
    private $requests_max;

    private $threads;
    private $peer;
    private $loginInfo;

    private $authClass;
    
    public function __construct($config) {

        if (PHP_MAJOR_VERSION < 8) {
            Log::log("Please consider updating to PHP8, supported version is 8.4", RADIUS_BASIC);
        }

        if (!function_exists("socket_create")) {    // check if extension is enabled
            die("ERROR: socket_create does not exist, please include socket extension (php_sockets.dll or php_sockets.so)");
        }

        $this->debugLevel = $config['debug'];
        $this->serverip=$config['serverip'];
        $this->serverport=$config['serverport'];
        Log::setDebugLevel($config['debug']);

        $this->attributes=new Attributes();
    }

    /**
     * Initialize server, bind IP and load dictionary
     * 
     * @param string $serverip
     * @param int $serverport
     */
    public function initialize() {

        $this->attributes->load_dictionary();
        $this->attributes->reverse_dictionary();

        Log::log("Running RADIUS server {$this->serverip} : {$this->serverport} on PHP " . PHP_VERSION . "", RADIUS_BASIC);    // server is running

        if (!($this->socket = socket_create(AF_INET, SOCK_DGRAM, 0))) { // create socket
            $errorcode = socket_last_error();
            $errormsg = socket_strerror($errorcode);

            die("Couldn't create socket: [$errorcode] $errormsg \n");
        }

        if (!socket_bind($this->socket, $this->serverip, $this->serverport)) {  // bind socket
            $errorcode = socket_last_error();
            $errormsg = socket_strerror($errorcode);

            die("Could not bind socket : [$errorcode] $errormsg \n");
        }
    }

    /**
     * Hex dump string
     * 
     * @param type $string
     * @return string
     */
    private function hex_dump($string): string {
        $hex = "";
        for ($c = 0; $c < strlen($string); $c++) {
            $hexnum = dechex(ord($string[$c]));
            if (strlen($hexnum) < 2) {
                $hexnum = "0" . $hexnum;
            }
            $hex .= $hexnum;
        }
        return $hex;
    }

    /**
     * Debug dump
     * 
     * Dumps content in hex format,
     * can write to file or output to disk,
     * uses RADIUS_DEBUG constant
     * 
     * @param string $content Content for dumping
     * @param string $filename Path to file where dump will be written to
     */
    private function debug_hex_dump($content, $filename = false) {
        $hex = $this->hex_dump($content);
        if ($filename) {
            file_put_contents(__DIR__ . "/" . $filename, $hex);
        } else {
            Log::log($hex, RADIUS_DEBUG);
        }
    }

    /**
     * Create user password based on auth and secret
     * Returns hash on success
     * 
     * @param string $password Password
     * @param string $auth Auth block sent from client
     * @param string $secret Secret for encrypting the block
     * @return boolean|string Return value - if success it will return created hash
     */
    private function create_user_password($password, $auth, $secret) {
        if (strlen($password) == 0) {      // empty?
            return false;
        }
        if (strlen($password) > 16) {  // cut to 16 if too large
            $password_pack = substr($password, 0, 16);
        } else
        if (strlen($password) < 16) {  // if less than 16 fill with 0
            $password_pack = str_pad($password, 16, chr(0x00));
            $password_pack_hex = $this->hex_dump($password_pack);
        } else {
            $password_pack = $password;
        }

        $phash = md5($secret . $auth);

        $enc = "";
        for ($c = 0; $c < 32; $c = $c + 2) {
            $xor = hexdec($phash[$c] . $phash[$c + 1]) ^ hexdec($password_pack_hex[$c] . $password_pack_hex[$c + 1]);
            $xorh = dechex($xor);
            if (strlen($xorh) < 2) {
                $xorh = "0" . $xorh;
            }
            $enc .= $xorh;
        }
        return $enc;
    }

    /**
     * Returns password for user
     * If no user or password it returns false
     * It should be overriden by descending class which
     * uses some method of checking like mysql
     * Lookup speed mainly affects performance, keep
     * this method as fast as possible,
     * best method may be to use cache or load entire db
     * into array if db is in some reasonable length
     * 
     * @param string $username Username for user auth
     * @return string Password for user, in plaintext
     */
    public function loginCheck($username) {
        if (!$this->authClass) {
            $authClass = "\\Cirko\\RadiusServer\\auth\\$this->authMethod";
            $this->authClass = new $authClass();
        }
        $this->loginInfo = $this->authClass->getLoginInfo($username);
        if ($this->loginInfo === false) {
            return false;
        }

        return isset($this->loginInfo['password'])?$this->loginInfo['password']:"";
    }

    /**
     * Match account login
     * Calls login_check for auth users
     * 
     * @param binary $auth Binary challenge
     * @param array $attr Array of attributes
     * @return boolean True if logged in successfully
     */
    private function loginMatch($auth, $attr) {
		
        $password = $this->loginCheck($attr["User-Name"]["value"]);
        if ($password===false) {    // login not found
            Log::log("No login for " . $attr["User-Name"]["value"], RADIUS_DEBUG);
            return false;
        }
        if (@$attr["CHAP-Challenge"]) { // https://tools.ietf.org/html/rfc2058#section-5.40
            $chapID = $attr['CHAP-Password']['value'][0];
            $encrypted_password = md5($chapID . $password . $attr["CHAP-Challenge"]["value"]);
            $requested_password = $this->hex_dump(substr($attr["CHAP-Password"]["value"], 1));
            return $requested_password == $encrypted_password;
        } else
        if (@$attr["CHAP-Password"]) {  // https://tools.ietf.org/html/rfc2058#section-5.3
            $chapID = $attr['CHAP-Password']['value'][0];
            $encrypted_password = md5($chapID . $password . $auth);
            $requested_password = $this->hex_dump(substr($attr["CHAP-Password"]["value"], 1));
            return $requested_password == $encrypted_password;
        } else
        if (@$attr["EAP-Message"]) {
            die("EAP unsupported.");
        } else
        if (@$attr["User-Password"]) {  // https://tools.ietf.org/html/rfc2058#section-5.2
            $encrypted_password = $this->create_user_password($password, $auth, $this->secret);
            $requested_password = $this->hex_dump($attr["User-Password"]["value"]);
            return $requested_password == $encrypted_password ;
        } else
        if (@$attr["MS-CHAP-Challenge"]) {
            die("MS-CHAP unsupported.");
        } else {
            die("Missing password.");
        }
        return false;
    }

    /**
     * Sets the attribute
     * 
     * @param string $attribute Attribute
     * @param string $value Value
     * @return boolean
     */
    public function set_attribute($attribute, $value) {
        Log::log("   {$attribute} -> {$value}", RADIUS_INFO);
        switch ($attribute) {
            case "Framed-IP-Address":
                $value = $this->encode_ip($value);
            default:
        }
        $code = @$this->radiusAttributesReverse[$attribute];
        if (!$code) {
            Log::log("   ******* Attribute {$attribute} unknown! *******", RADIUS_INFO);
            return false;
        }

        $packed = pack("CCa" . strlen($value), $code, strlen($value) + 2, $value);
        return $packed;
    }

    /**
     * Encode IP to correct binary format
     * 
     * @param type $ip
     * @return type
     */
    public function encode_ip($ip) {
        $ip_parts = explode(".", $ip);
        $ip_packed = pack("CCCC", $ip_parts[0], $ip_parts[1], $ip_parts[2], $ip_parts[3]);
        return $ip_packed;
    }

    /**
     * Process request code
     * Code is taken from pkta array
     * 
     * @param array $pkta Associative array of packet info
     * @param string $pkt
     * @param int $auth
     * @param int $attr
     * @param string $remote_ip Remote IP address where request came from
     * @param string $remote_port Remote port where request was sent to
     */
    private function process_code($pkta, $pkt, $auth, $attr, $remote_ip, $remote_port) {

        switch ($pkta["code"]) {    // Request code
            case $this->attributes->getCodeReverse("Access-Request"):
                $password_match = $this->loginMatch($auth, $attr);
                if ($password_match) {
                    // Access-Accept
                    Log::log("Reply: Access-Accept", RADIUS_INFO);
                    $reply = '';
                    foreach ($this->loginInfo as $attr => $val) {
                        if ($attr == 'password') {
                            continue;
                        }
                        $reply .= $this->set_attribute($attr, $val);
                    }
                    $response_code = $this->radiusCodesReverse["Access-Accept"];   // Accept the request
                    $response_length = 3 + 16 + 1 + strlen($reply);
                    $response_string = pack("CCna16a" . strlen($reply) . "a" . strlen($this->secret), $response_code, $pkta["id"], $response_length, $auth, $reply, $this->secret);
                    $response_auth = md5($response_string, true);
                    $response_string_binary = pack("CCna16a" . strlen($reply), $response_code, $pkta["id"], $response_length, $response_auth, $reply);
                    $this->radius_reply($response_string_binary, $remote_ip, $remote_port);
                } else {
                    // Access-Reject
                    Log::log("Reply: Access-Reject", RADIUS_INFO);
                    $response_code = $this->attributes->getCodeReverse("Access-Reject");   // Reject the request
                    $response_length = 3 + 16 + 1;
                    $response_string = pack("CCna16a" . strlen($this->secret), $response_code, $pkta["id"], $response_length, $auth, $this->secret);
                    $response_auth = md5($response_string, true);
                    $response_string_binary = pack("CCna16", $response_code, $pkta["id"], $response_length, $response_auth);
                    $this->radius_reply($response_string_binary, $remote_ip, $remote_port);
                }
                break;
            case $this->radiusCodesReverse["Accounting-Request"]:
                Log::log("Reply: Accounting-Request", RADIUS_INFO);
                break;
            default:
        }
    }

    /**
     * Process single request
     * 
     * @param string $pkt
     * @param string $remote_ip Remote IP address
     * @param int $remote_port Remote port
     * @return boolean True on success, false on error
     */
    public final function process_request($pkt, $remote_ip, $remote_port) {

        $pkta = [// make packet structure
            "code" => ord($pkt[0]),
            "id" => ord($pkt[1]),
            "len" => (ord($pkt[2]) * 255) + ord($pkt[3]),
        ];

        Log::log("Request: {$this->peer} {$this->attributes->getCode($pkta["code"])} id {$pkta["id"]} len {$pkta["len"]}", RADIUS_CONNECTION);

        if (strlen($pkt) < 21) {
            Log::log("Packet less than 21, probalby empty request", RADIUS_INFO);
            return false;
        }

        $auth = substr($pkt, 4, 16);
        $avps = substr($pkt, 20);
        $attr = $this->attributes->decode_attr($pkta["code"], $avps, $pkta["len"] - 20);
        Log::log("Reply: ", RADIUS_INFO);
        $this->process_code($pkta, $pkt, $auth, $attr, $remote_ip, $remote_port);

        return true;
    }

    public function parseConfig(array $config) {
        $this->receive_buffer = (int) $config['receive_buffer'];
        $this->serverip = $config['serverip'];
        $this->serverport = $config['serverport'];
        $this->secret = $config['secret'];
        $this->authMethod = $config['auth_method'];
    }

    private function savePacket(int $id, string $content):void {
        file_put_contents(__DIR__."/../../packets/packet-".$id.".pkt",$content);
    }

    /**
     * MAIN RADIUS LOOP
     * Waits for packet on initialized socket
     * and process request (which replies)
     * It is run in dead loop so use CTRL-C to stop it.
     * 
     */
    public function radius_run(array $config) {
        $this->parseConfig($config);
        $packet=0;
        do {
            if ($this->time == 0) {
                $this->time = microtime(true);
                $last_requests = 0;
            }

            Log::log("Waiting for packet", RADIUS_CONNECTION);
            $pkta = []; // array of info about packet
            $r = socket_recvfrom($this->socket, $pkt, $this->receive_buffer, 0, $remote_ip, $remote_port);  // Receive data
            $this->savePacket($packet,$pkt);

            $this->requests++;

            if (strlen($pkt) < 4) { // Invalid packet size
                Log::log("Malformed packet, reply size less than 4!", RADIUS_INFO);
                continue;
            }
            $microtime = microtime(true);
            $elapsed = $microtime - $this->time;
            if ($elapsed > 1) {
                $req = $this->requests - $last_requests;
                if ($req < $this->requests_min || $this->requests_min < 1) {
                    $this->requests_min = $req;
                }
                if ($req > $this->requests_max) {
                    $this->requests_max = $req;
                }
                Log::log("Requests: {$req}/sec minimum {$this->requests_min} maximum {$this->requests_max}", RADIUS_BASIC);
                $last_requests = $this->requests;
                $this->time = $microtime;
            }

            if ($this->threads) {   // threading exists on server, use it. It's not recommended to do so.
                $this->runThread();
            } else {
                $this->process_request($pkt, $remote_ip, $remote_port); // process request
            }
            $packet++;
        } while ($pkt !== false);   // dead loop, process next packet
    }

    private function runThread() {
        $newthread = new radiusThreads($pkt, $remote_ip, $remote_port);
        $this->threadArray[] = &$newthread;
        $newthread->start();
    }

    /**
     * Reply to request
     * 
     * @param type $reply
     * @param type $remote_ip
     * @param type $remote_port
     */
    private function radius_reply($reply, $remote_ip, $remote_port) {
        socket_sendto($this->socket, $reply, strlen($reply), 0, $remote_ip, $remote_port);
    }

}
