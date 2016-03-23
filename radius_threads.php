<?php

// Threading class for radius
class radiusThreads extends Thread {

    public $pkt;
    public $remote_ip;
    public $remote_port;
    public $radiusServer = FALSE;

    public function __construct($pkt, $remote_ip, $remote_port) {
        $this->pkt = $pkt;
        $this->remote_ip = $remote_ip;
        $this->remote_port = $remote_port;
    }

    /**
     * Run thread (called by start)
     */
    public function run() {
        $this->radiusServer = new radius_server();
        $this->radiusServer->load_dictionary();
        $this->radiusServer->reverse_dictionary();
        $this->radiusServer->process_request($this->pkt, $this->remote_ip, $this->remote_port);
    }

}
