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

namespace server\base;

/**
 * Base RADIUS server class
 * 
 * This class implements the core functionality for a RADIUS server that handles
 * network communication and basic packet processing.
 * 
 * @version 1.0
 * @category radius
 * @package radius-server
 * @author Dragutin Cirkovic <dragonmen@gmail.com>
 */
class BaseRadiusServer {

    /**
     * Socket resource for network communication
     * @var resource|null
     */
    protected $socket;
    
    /**
     * Peer information
     * @var string|null
     */
    protected $peer;

    protected $radiusCodesReverse;

    protected $radius_codes;

    protected $radius_attributes;

    /**
     * Accounting packet attribute definitions
     * @var array
     */
    protected $radius_acc_atributes = [];
    
    /**
     * Receive buffer size
     * @var int
     */
    protected $receive_buffer = 65535;
    
    /**
     * Server IP address
     * @var string
     */
    protected $serverip = "0.0.0.0";
    
    /**
     * Server port number
     * @var int
     */
    protected $serverport = 1812;
    
    /**
     * Shared secret for authentication
     * @var string
     */
    protected $secret = "secret";
    
    /**
     * Timer for performance tracking
     * @var float
     */
    protected $time = 0;
    
    /**
     * Total request count
     * @var int
     */
    protected $requests = 0;
    
    /**
     * Minimum requests per second
     * @var int
     */
    protected $requests_min = 0;
    
    /**
     * Maximum requests per second
     * @var int
     */
    protected $requests_max = 0;
    
    /**
     * Debug level (0=off, 1=basic, 2=connection, 3=info, 4=debug)
     * @var int
     */
    public $debugLevel = RADIUS_BASIC;
    
    /**
     * Log file path (FALSE if not logging to file)
     * @var string|bool
     */
    protected $log_file = FALSE;
    
    /**
     * Authentication method name
     * @var string|null
     */
    protected $authMethod = NULL;
    
    /**
     * Authentication class instance
     * @var object|null
     */
    protected $authClass = NULL;
    
    /**
     * Thread usage flag (not implemented in this version)
     * @var bool
     */
    protected $threads = FALSE;
    
    /**
     * Array of threads (not used in this version)
     * @var array
     */
    protected $threadArray = [];
    
    /**
     * Login information for current request
     * @var array|null
     */
    protected $loginInfo;

    /**
     * Constructor - initializes the RADIUS server
     * 
     * @param string|null $serverip IP address to bind to (optional)
     * @param int|null $serverport Port number to listen on (optional)
     * 
     * @return void
     */
    public function __construct() {
        // PHP 8.5 compatibility: Updated deprecated PHP_MAJOR_VERSION check
        if (version_compare(PHP_VERSION, '7.0.0', '<')) {
            $this->log("Please consider updating to PHP 7+, as you will get 4x better performance", RADIUS_BASIC);
        }

        // Check if socket extension is enabled - required for UDP communication
        if (!function_exists("socket_create")) {    
            die("ERROR: socket_create does not exist, please include socket extension (php_sockets.dll or php_sockets.so)");
        }
        
        // Initialize radiusCodesReverse if not already done (in case it's called directly)
        // Ensure radius_codes is properly initialized before flipping
        if (!isset($this->radius_codes) || !is_array($this->radius_codes)) {
            $this->radius_codes = [
                1 => "Access-Request",
                2 => "Access-Accept", 
                3 => "Access-Reject",
                4 => "Accounting-Request",
                5 => "Accounting-Response",
                11 => "Access-Challenge",
                12 => "Status-Server",
                13 => "Status-Client",
            ];
        }
        
        if (!isset($this->radiusCodesReverse) || empty($this->radiusCodesReverse)) {
            $this->radiusCodesReverse = array_flip($this->radius_codes);
        }
    }

    /**
     * Initialize server, bind IP and load dictionary
     * 
     * @param string|null $serverip IP address to bind to (optional)
     * @param int|null $serverport Port number to listen on (optional)
     * 
     * @return void
     */
    public function initialize(?string $serverip = null, ?int $serverport = null): void {

        // Set server IP and port if provided
        if ($serverip !== null) {    // server ip is defined
            $this->serverip = $serverip;
            $this->serverport = $serverport;
        }

        // Log server startup information
        $this->log("Running RADIUS server {$this->serverip} : {$this->serverport} on PHP " . PHP_VERSION . "", RADIUS_BASIC);    // server is running

        // Create UDP socket for communication
        if (!($this->socket = socket_create(AF_INET, SOCK_DGRAM, 0))) { // create socket
            $errorcode = socket_last_error();
            $errormsg = socket_strerror($errorcode);

            die("Couldn't create socket: [$errorcode] $errormsg \n");
        }

        // Bind the socket to the specified address and port
        if (!socket_bind($this->socket, $this->serverip, $this->serverport)) {  // bind socket
            $errorcode = socket_last_error();
            $errormsg = socket_strerror($errorcode);

            die("Could not bind socket : [$errorcode] $errormsg \n");
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
        if ($debug === null || $this->debugLevel >= $debug) {  // debug on, write messages
            if ($this->log_file) {  // log file defined?
                $r = file_put_contents($this->log_file, $message, FILE_APPEND); // add to log
                if ($r === false) { // write to log failed?
                    echo "ERROR: Could not write to log!\n";
                }
            } else {
                echo $message . "\n";   // echo to console
            }
        }
    }

    /**
     * Encode IP to correct binary format
     * 
     * @param string $ip IP address to encode
     * @return string Encoded IP address
     */
    public function encode_ip(string $ip): string {
        $ip_parts = explode(".", $ip);
        $ip_packed = pack("CCCC", $ip_parts[0], $ip_parts[1], $ip_parts[2], $ip_parts[3]);
        return $ip_packed;
    }

    /**
     * Process single request
     * 
     * @param string $pkt Full packet data
     * @param string $remote_ip Remote IP address
     * @param int $remote_port Remote port
     * @return bool True on success, false on error
     */
    public function process_request(string $pkt, string $remote_ip, int $remote_port): bool {

        $pkta = [// make packet structure
            "code" => ord($pkt[0]),
            "id" => ord($pkt[1]),
            "len" => (ord($pkt[2]) * 255) + ord($pkt[3]),
        ];

        $this->log("Request: {$this->peer} {$this->radius_codes[$pkta["code"]]} id  {$pkta["id"]} len {$pkta["len"]}", RADIUS_CONNECTION);

        // DEBUG: capture the exact raw packet so it can be replayed/analyzed offline
        //$this->debug_hex_dump($pkt, "raw_packet_capture.hex");

        if (strlen($pkt) < 21) {
            $this->log("Packet less than 21, probably empty request", RADIUS_INFO);
            return false;
        }

        $auth = substr($pkt, 4, 16);
        $avps = substr($pkt, 20);
        $attr = $this->decode_attr($pkta["code"], $avps, $pkta["len"] - 20);
        $this->log("Reply: ", RADIUS_INFO);
        $this->process_code($pkta, $pkt, $auth, $attr, $remote_ip, $remote_port);

        return true;
    }

    /**
     * MAIN RADIUS LOOP
     * Waits for packet on initialized socket
     * and process request (which replies)
     * It is run in dead loop so use CTRL-C to stop it.
     * 
     * @param array $config Configuration array
     * @return void
     */
    public function radius_run(array $config): void {
        $this->parseConfig($config);
        $last_requests=0;
        do {
            if ($this->time == 0) {
                $this->time = microtime(true);
                $last_requests = 0;
            }

            $this->log("Waiting for packet", RADIUS_CONNECTION);
            $pkta = []; // array of info about packet
            $r = socket_recvfrom($this->socket, $pkt, $this->receive_buffer, 0, $remote_ip, $remote_port);  // Receive data

            $this->requests++;

            if (strlen($pkt) < 4) { // Invalid packet size
                $this->log("Malformed packet, reply size less than 4!", RADIUS_INFO);
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
                $this->log("Requests: {$req}/sec minimum {$this->requests_min} maximum {$this->requests_max}", RADIUS_BASIC);
                $last_requests = $this->requests;
                $this->time = $microtime;
            }

            if ($this->threads) {   // threading exists on server, use it
                $newthread = new radiusThreads($pkt, $remote_ip, $remote_port); // instance thread extended class with parameters
                $this->threadArray[] = &$newthread;    // put thread list to array so we can manage it, do not copy var, only pass pointer
                $newthread->start();    // start thread
            } else {
                $this->process_request($pkt, $remote_ip, $remote_port); // process request
            }
        } while ($pkt !== false);   // dead loop, process next packet
    }

    /**
     * Reply to request
     * 
     * @param string $reply Response data to send back
     * @param string $remote_ip Remote IP address
     * @param int $remote_port Remote port
     * @return void
     */
    protected function radius_reply(string $reply, string $remote_ip, int $remote_port): void {
        socket_sendto($this->socket, $reply, strlen($reply), 0, $remote_ip, $remote_port);
    }

    /**
     * Parse configuration options
     * 
     * @param array $config Configuration array
     * @return void
     */
    protected function parseConfig(array $config): void {
        $this->receive_buffer = (int) $config['receive_buffer'];
        $this->serverip = $config['serverip'];
        $this->serverport = $config['serverport'];
        $this->secret = $config['secret'];
        $this->authMethod = $config['auth_method'];
    }

    /**
     * Process request code
     * Code is taken from pkta array
     * 
     * @param array $pkta Associative array of packet info
     * @param string $pkt Full packet data
     * @param string $auth Authentication data
     * @param array $attr Array of attributes
     * @param string $remote_ip Remote IP address where request came from
     * @param string $remote_port Remote port where request was sent to
     * @return void
     */
    protected function process_code(array $pkta, string $pkt, string $auth, array $attr, string $remote_ip, string $remote_port): void {

        switch ($pkta["code"]) {    // Request code
            case $this->radiusCodesReverse["Access-Request"]:
                $password_match = $this->loginMatch($auth, $attr);
                if ($password_match) {
                    // Access-Accept
                    $this->log("Reply: Access-Accept", RADIUS_INFO);
                    $reply = '';
                    foreach ($this->loginInfo as $attr => $val) {
                        if ($attr == 'password') {
                            continue;
                        }
                        $reply .= $this->set_attribute($attr, $val);
                    }
                    $response_code = $this->radiusCodesReverse["Access-Accept"];   //access-accept
                    $response_length = 3 + 16 + 1 + strlen($reply);
                    $response_string = pack("CCna16a" . strlen($reply) . "a" . strlen($this->secret), $response_code, $pkta["id"], $response_length, $auth, $reply, $this->secret);
                    $response_auth = md5($response_string, true);
                    $response_string_binary = pack("CCna16a" . strlen($reply), $response_code, $pkta["id"], $response_length, $response_auth, $reply);
                    $this->radius_reply($response_string_binary, $remote_ip, $remote_port);
                } else {
                    // Access-Reject
                    $this->log("Reply: Access-Reject", RADIUS_INFO);
                    $response_code = $this->radiusCodesReverse["Access-Reject"];   //access-accept
                    $response_length = 3 + 16 + 1;
                    $response_string = pack("CCna16a" . strlen($this->secret), $response_code, $pkta["id"], $response_length, $auth, $this->secret);
                    $response_auth = md5($response_string, true);
                    $response_string_binary = pack("CCna16", $response_code, $pkta["id"], $response_length, $response_auth);
                    $this->radius_reply($response_string_binary, $remote_ip, $remote_port);
                }
                break;
            case $this->radiusCodesReverse["Accounting-Request"]:
                $this->log("Reply: Accounting-Request", RADIUS_INFO);
                break;
            default:
        }
    }

    /**
     * Decode attributes from radius packet
     * 
     * @param int $code Packet code
     * @param string $request Request data
     * @param int $size Size of the request
     * @return array Decoded attributes
     */
    protected function decode_attr(int $code, string $request, int $size): array {
        $csize = 0;
        $attr = [];
        while ($csize < $size) {
            // Ensure radiusCodesReverse is initialized before use
            if (!isset($this->radiusCodesReverse) || empty($this->radiusCodesReverse)) {
                // Initialize if not already done - this should normally be done by the child class
                $this->radiusCodesReverse = array_flip($this->radius_codes);
            }
            
            $attrCode = ord($request[$csize]);
            if ($code == $this->radiusCodesReverse["Access-Request"]) {
                $type = $this->radius_attributes[$attrCode] ?? ("Unknown-Attribute-{$attrCode}");
            } elseif ($code == $this->radiusCodesReverse["Accounting-Request"]) {
                $type = $this->radius_acc_atributes[$attrCode] ?? ("Unknown-Attribute-{$attrCode}");
            } else {
                // For unknown packet types, try to still name the attribute
                $type = $this->radius_attributes[$attrCode]
                    ?? ($this->radius_acc_atributes[$attrCode] ?? ("Unknown-Attribute-{$attrCode}"));
                $this->log("Unknown packet type {$code}, decoding as attribute: {$type}", RADIUS_BASIC);
            }

            // IMPORTANT: always skip the whole attribute (type + length + value) by its
            // declared length. Advancing by anything other than $len misaligns the
            // decode cursor and corrupts every attribute that follows (this was the
            // cause of CHAP-Password / User-Password being lost on multi-attribute
            // requests such as Mikrotik).
            $len = ord($request[$csize + 1]);
            if ($len < 2) {  // malformed length: stop to avoid an infinite loop
                $this->log("Malformed attribute length {$len} at offset {$csize}, stopping decode", RADIUS_INFO);
                break;
            }
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
            if (RADIUS_INFO <= $this->debugLevel) {  // debug on, write messages
                $value = $this->format_attr_value($type, $value);
            }
            $this->log("   {$type} => {$value}", RADIUS_INFO);
        }
        return $attr;
    }

    /**
     * Hex dump string
     * 
     * @param string $string Input string to convert to hex
     * @return string Hexadecimal representation of the input
     */
    protected function hex_dump(string $string): string {
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
     * Render a decoded attribute value in a human-readable form based on its
     * type, instead of a raw hex dump. Keeps the existing hex representation
     * for binary attributes (like CHAP), while making numbers, IP addresses
     * and MAC-like station IDs easy to read in the request log.
     *
     * @param string $type  Attribute name (e.g. "NAS-Port", "CHAP-Challenge")
     * @param string $value Raw binary value (already stripped of type/len header)
     * @return string Human-readable representation of the value
     */
    protected function format_attr_value(string $type, string $value): string {
        $len = strlen($value);
        if ($len === 0) {
            return "";
        }

        // 4-byte integer attributes (NAS-Port, NAS-Port-Type, Service-Type,
        // Framed-Protocol, Session-Timeout, ...). NAS-Port-Type is a small
        // enum; we still show the raw decimal, which is what operators expect.
        if ($len === 4 && $this->is_int_attr($type)) {
            return (string) ((ord($value[0]) << 24) | (ord($value[1]) << 16) | (ord($value[2]) << 8) | ord($value[3]));
        }

        // 4-byte IPv4 addresses.
        if ($len === 4 && $this->is_ipv4_attr($type)) {
            return sprintf("%d.%d.%d.%d", ord($value[0]), ord($value[1]), ord($value[2]), ord($value[3]));
        }

        // CHAP-Password: first byte is the CHAP id, rest is the 16-byte MD5
        // digest. Show as "id=XX digest=..." so it's clear which part is which.
        if ($type === 'CHAP-Password' && $len >= 1) {
            $id = ord($value[0]);
            return sprintf("id=%d digest=%s", $id, $this->hex_dump(substr($value, 1)));
        }

        // MAC-like station IDs: "00:50:56:25:8B:97" is already human-readable.
        if (preg_match('/^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$/', $value)) {
            return strtoupper($value);
        }

        // Short printable strings (User-Name, Called/Calling-Station-Id,
        // NAS-Port-Id like "WAN", NAS-Identifier, Filter-Id, ...): show as text.
        if ($len <= 64 && preg_match('/^[\x20-\x7e]+$/', $value)) {
            return $value;
        }

        // Everything else (CHAP-Challenge, EAP-Message, binary blobs,
        // long or non-printable values): hex.
        return $this->hex_dump($value);
    }

    /**
     * @param string $type Attribute name
     * @return bool Whether the attribute is a 4-byte integer in the RADIUS dictionary
     */
    protected function is_int_attr(string $type): bool {
        static $int_attrs = [
            'NAS-Port', 'NAS-Port-Type', 'Service-Type', 'Framed-Protocol',
            'Session-Timeout', 'Framed-MTU', 'Login-Lifetime', 'Port-Limit',
            'Acct-Session-Time', 'Acct-Terminate-Cause', 'Acct-Delay',
            'Acct-Input-Octets', 'Acct-Output-Octets', 'Acct-Input-Packets',
            'Acct-Output-Packets', 'Acct-Session-Id', 'Acct-Authentic',
            'Acct-Status-Type', 'Acct-Input-Gigawords', 'Acct-Output-Gigawords',
            'Idle-Timeout', 'Login-Lifetime',
        ];
        return in_array($type, $int_attrs, true);
    }

    /**
     * @param string $type Attribute name
     * @return bool Whether the attribute holds a 4-byte IPv4 address
     */
    protected function is_ipv4_attr(string $type): bool {
        static $ipv4_attrs = [
            'Framed-IP-Address', 'NAS-IP-Address',
        ];
        return in_array($type, $ipv4_attrs, true);
    }

    /**
     * Debug dump
     * 
     * Dumps content in hex format,
     * can write to file or output to disk,
     * uses RADIUS_DEBUG constant
     * 
     * @param string $content Content for dumping
     * @param string|null $filename Path to file where dump will be written to (optional)
     * @return void
     */
    protected function debug_hex_dump(string $content, ?string $filename = null): void {
        $hex = $this->hex_dump($content);
        if ($filename) {
            file_put_contents(__DIR__ . "/" . $filename, $hex);
        } else {
            $this->log($hex, RADIUS_DEBUG);
        }
    }

    /**
     * Match account login
     * Calls login_check for auth users
     * 
     * @param string $auth Binary challenge
     * @param array $attr Array of attributes
     * @return bool True if logged in successfully
     */
    protected function loginMatch(string $auth, array $attr): bool {
        $password = $this->loginCheck($attr["User-Name"]["value"]);
        if (!$password) {    // login not found
            $this->log("No login for " . $attr["User-Name"]["value"], RADIUS_DEBUG);
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
     * Create user password based on auth and secret
     * Returns hash on success
     * 
     * @param string $password Password to encrypt
     * @param string $auth Auth block sent from client
     * @param string $secret Secret for encrypting the block
     * @return string|bool Return value - if success it will return created hash, otherwise false
     */
    protected function create_user_password(string $password, string $auth, string $secret) {
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
     * Get authentication class
     * 
     * @return object|null Authentication class instance or null if not set
     */
    protected function getAuthClass() {
        if ($this->authClass === NULL) {
            $class = "\\auth\\" . $this->authMethod;
            if (class_exists($class)) {
                $this->authClass = new $class();
            } else {
                $this->log("Authentication class {$class} not found", RADIUS_INFO);
                return null;
            }
        }
        return $this->authClass;
    }

    /**
     * Check login
     * 
     * Stores the full login info (attributes for the Access-Accept reply)
     * in $this->loginInfo and returns the user's password.
     * 
     * @param string $username Username to check
     * @return string|bool Password or false if not found
     */
    protected function loginCheck(string $username) {
        $authClass = $this->getAuthClass();
        if ($authClass !== null && method_exists($authClass, 'getLoginInfo')) {
            $this->loginInfo = $authClass->getLoginInfo($username);
            if ($this->loginInfo === false || !is_array($this->loginInfo)) {
                $this->loginInfo = null;
                return false;
            }
            return $this->loginInfo['password'] ?? false;
        }
        return false;
    }

}