<?php

use PHPUnit\Framework\TestCase;

final class RadiusServerTest extends TestCase
{
    public function testInit(): void
    {
        require __DIR__ . DIRECTORY_SEPARATOR . "/../init.php";

        $radius = new \Cirko\RadiusServer\server\RadiusServer($config);
        $radius->initialize();

        $this->assertSame($config['auth_method'], "File");
    }

    public function testDict(): void
    {
        require __DIR__ . DIRECTORY_SEPARATOR . "/../init.php";

        $radius = new \Cirko\RadiusServer\server\RadiusServer($config);
        $radius->initialize();

        $this->assertSame($radius->radiusCodesReverse['Access-Request'], 1);
        $this->assertSame($radius->radius_codes[1], 'Access-Request');
        $this->assertSame($radius->radiusAttributesReverse['User-Name'], 1);
        $this->assertSame($radius->radius_attributes[1], 'User-Name');
    }

    public function testPacket(): void
    {
        if (!file_exists(__DIR__.'/../packets/packet-pppoe.pkt')) {
            return;
        }

        require __DIR__ . DIRECTORY_SEPARATOR . "/../init.php";

        $radius = new \Cirko\RadiusServer\server\RadiusServer($config);
        $radius->initialize();
        $radius->parseConfig($config);

        $this->assertSame($config['auth_method'], "File");

        $pkt=file_get_contents(__DIR__.'/../packets/packet-pppoe.pkt');
        $remote_ip="127.0.0.1";
        $remote_port=1234;

        $r=$radius->processRequest($pkt, $remote_ip, $remote_port); // process request

        $this->assertSame($r, true);
    }
}
