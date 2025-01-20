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

/**
 * Radius server class
 * 
 * @version 1.0
 * @category radius
 * @package radius-server
 * @author Dragutin Cirkovic <dragonmen@gmail.com>
 */
class RadiusCodes {

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
    public $radiusAttributesReverse = [];
    public $vendorRadiusAttributes = [];
    public $vendorRadiusAttributesReverse = [];
    public $radiusCodesReverse = [];
    protected $socket;
    protected $peer;
    protected $receive_buffer = 65535;
    protected $serverip = "0.0.0.0";
    protected $serverport = 1812;
    protected $secret = "secret";
    protected $time = 0;
    protected $requests = 0;
    protected $requests_min = 0;
    protected $requests_max = 0;
    public $debugLevel = RADIUS_BASIC;   // 0=off, 1=basic, 2=connection, 3=info, 4=debug
    protected $log_file = FALSE;   // where to save logs
    protected $authMethod = NULL;
    protected $authClass = NULL;
    protected $threads = FALSE; // boolean to flag thread usage, don't do it
    protected $threadArray = [];
    protected $loginInfo;
}
