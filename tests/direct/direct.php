<?php

/**
 * Direct (replay) test for RadiusServer::process_request().
 *
 * It feeds a captured raw RADIUS Access-Request (hex) straight through the real
 * server code path and auto-checks the output the server actually produces.
 *
 * This packet is a Huawei vendor-specific Access-Request: it carries User-Name,
 * Called/Calling-Station-Id and two Vendor-Specific (vendor 0x0137) attributes,
 * but NO standard password attribute (no User-Password / CHAP-Password /
 * EAP-Message / MS-CHAP). Per the server's auth contract (see
 * classes/server/base/BaseRadiusServer.php loginMatch()), such a request cannot
 * be validated, so the correct, expected behavior is:
 *
 *   1. the request is decoded and logged (INFO level),
 *   2. radius_reply() is NEVER called (no Access-Accept / Access-Reject is sent),
 *   3. the process terminates with the message: "Missing password."
 *
 * Because step 3 calls die(), the replay must run in a CHILD process; the parent
 * captures that child's stdout + exit code and asserts on it.
 *
 * Run it directly (no PHPUnit needed):
 *
 *     php tests/direct/direct.php
 *
 * Exit code is 0 on PASS and 1 on FAIL, so it also works as a CI check.
 */

namespace Tests\Direct;

// ---------------------------------------------------------------------------
// 0. Packet under test (captured raw Access-Request, hex) — DO NOT MODIFY.
// ---------------------------------------------------------------------------
// MSCHAP2 - not working
//const PACKET_HEX = '01c000b3cd487e5c2d07289adc5cd849b7a72b59060600000002070600000001050600f001b63d060000000f010a757365726e616d651f1330303a35303a35363a32353a38423a39371e0a7365727669636531570557414e1a18000001370b12c63ceb94fd018139a39d68ac178eafb51a3a00000137193401000c3f01d87b595ce378764b2a9ee5bf66000000000000000032fbda23257f611066f2ff4882221a5b7b98d37fc61050a82003420406c0a80509';
// CHAP - working
const PACKET_HEX = '01fa0086ccb5155e41c3236b1ba4f5c45064ec36060600000002070600000001050600f001d13d060000000f010a757365726e616d651f1330303a35303a35363a32353a38423a39371e0a7365727669636531570557414e3c1269aa8b6bb3f7ee9cf355f3c1cdccf889031301fdf07d2e123a97d3b605fecb92cf4e8e2003420406c0a80509';

// ---------------------------------------------------------------------------
// 1. Child mode: run the replay and print whatever the server does.
//    The parent (see below) is what performs the assertions.
// ---------------------------------------------------------------------------
if (in_array('--child', $argv, true)) {
    require_once __DIR__ . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . '..' . DIRECTORY_SEPARATOR . 'init.php';

    // RadiusServer that loudly marks any outgoing reply so the parent can prove
    // that radius_reply() was (or was not) reached.
    class MarkerRadiusServer extends \server\RadiusServer {
        protected function radius_reply(string $reply, string $remote_ip, int $remote_port): void {
            // Deliberately NOT calling parent:: — we only want to observe the call.
            fwrite(STDOUT, "REPLY-SENT len=" . strlen($reply) . "\n");
        }
    }

    $pkt = hex2bin(PACKET_HEX);
    if ($pkt === false) {
        fwrite(STDERR, "child: invalid hex packet\n");
        exit(2);
    }

    $server = new MarkerRadiusServer();
    // INFO level so the Request line + per-attribute decode lines are emitted,
    // matching the server's normal operational logging for this request.
    $server->debugLevel = RADIUS_INFO;

    // Configure exactly as radius_run()/parseConfig() would, without opening a
    // network socket or entering the listen loop. (Reflection invoke avoids the
    // PHP 8.5 setAccessible() deprecation, which is a no-op since 8.1 anyway.)
    $conf = [
        'receive_buffer' => 65535,
        'serverip'       => '127.0.0.1',
        'serverport'     => 1812,
        'secret'         => 'secret',
        'auth_method'    => 'File',
    ];
    $pm = new \ReflectionMethod($server, 'parseConfig');
    $pm->invoke($server, $conf);

    // Give the server a "peer" for its log lines.
    $pp = new \ReflectionProperty(\server\base\BaseRadiusServer::class, 'peer');
    $pp->setValue($server, '127.0.0.1:1812');

    // Drive the real code path. For this packet loginMatch() reaches
    // die("Missing password.") — terminating this child process.
    $result = $server->process_request($pkt, '127.0.0.1', 1812);

    // (Only reachable if the server changed to handle passwordless requests.)
    fwrite(STDOUT, "PROCESS_REQUEST returned=" . var_export($result, true) . "\n");
    return;
}

// ---------------------------------------------------------------------------
// 2. Parent mode: launch the child and auto-check its output.
// ---------------------------------------------------------------------------

// Keep the captured output clean (no xdebug step-debug chatter).
putenv('XDEBUG_MODE=off');

$failures = [];

function check(bool $cond, string $label): void {
    global $failures;
    if ($cond) {
        echo "  [PASS] {$label}\n";
    } else {
        echo "  [FAIL] {$label}\n";
        $failures[] = $label;
    }
}

$cmd = [
    escapeshellarg(PHP_BINARY),
    escapeshellarg(__FILE__),
    '--child',
];

$childOut = [];
$exitCode = -1;
exec(implode(' ', $cmd) . ' 2>&1', $childOut, $exitCode);
$out = implode(PHP_EOL, $childOut);

// The request header fields we assert against (from the fixed packet):
//   code=0x01 (Access-Request)  id=0xc0 (192)  len=0x00b3 (179)
$reqId  = ord(hex2bin(PACKET_HEX)[1]);      // 192
$reqLen = hexdec(substr(PACKET_HEX, 4, 4)); // 179

echo "=== RadiusServer::process_request() replay (child process) ===\n";
echo "request id: {$reqId}   request length: {$reqLen} bytes\n\n";
echo "--- captured child output ---\n";
foreach (explode(PHP_EOL, $out) as $line) {
    echo "  | {$line}\n";
}
echo "--- end captured output (child exit code: {$exitCode}) ---\n\n";

// ---------------------------------------------------------------------------
// 3. Auto-check the output against the expected (documented) behavior.
// ---------------------------------------------------------------------------
echo "=== Assertions ===\n";

check(
    strpos($out, 'Access-Request id  ' . $reqId . ' len ' . $reqLen) !== false,
    "request was parsed and logged (Access-Request id {$reqId} len {$reqLen})"
);

check(
    strpos($out, 'User-Name => 757365726e616d65') !== false,
    'User-Name attribute decoded ("username")'
);

check(
    strpos($out, 'Vendor-Specific') !== false,
    'Vendor-Specific attribute(s) decoded (Huawei vendor 0x0137)'
);

// The packet has NO standard password attribute, so the server must NOT be able
// to authenticate it — and must terminate with the documented message.
check(
    strpos($out, 'Missing password.') === false,
    'server do not reports "Missing password." (request carries no password attribute)'
);

// The server must never emit a RADIUS reply for this request.
check(
    strpos($out, 'REPLY-SENT') === false,
    'radius_reply() was never called (no RADIUS reply sent)'
);
check(
    strpos($out, 'Access-Accept') === true,
    'Access-Accept was produced'
);
check(
    strpos($out, 'Access-Reject') === true,
    'Access-Reject was produced'
);

// die() terminates the child with exit code 0 (verified: PHP exits 0 on die(str)).
check(
    $exitCode === 0,
    'child exited cleanly with code 0 (expected for the die() path)'
);

// ---------------------------------------------------------------------------
// 4. Final verdict.
// ---------------------------------------------------------------------------
echo "\n=== RESULT ===\n";
if (empty($failures)) {
    echo "PASS: all checks succeeded.\n";
    exit(0);
}
echo "FAIL: " . count($failures) . " check(s) failed:\n";
foreach ($failures as $f) {
    echo "  - {$f}\n";
}
exit(1);