<?php 
namespace auth;
class Nice {

    private $auth = [];
    private $loadedAt = NULL;
    private $loadEvery = 60;
    private $d = NULL;
    private function loadDB() {
        $this->loadedAt = 0;
        
        $this->d = new \server\NiceDB();
        $data = $this->d->select('users');
        foreach($data as $key => $val){
            $this->auth[$val['User-Name']] = $val;
        }
    }

    public function getLoginInfo(string $username) {
        if (empty($this->auth) || $this->loadedAt < microtime(true) - $this->loadEvery) {
            $this->loadDB();
        }
        return $this->auth[$username];
    }

}
