<?php
namespace server;
class NiceDB {
	private $_db_dir = './data/';
	private $_tablename = 'default';
	private $_extension = 'json';
	private $_encrypt = false;
	private $db_cache = [];
	public function __construct(array $config = []) {
		$config = array_merge([
			'extension' => $this->_extension,
			'encrypt' => $this->_encrypt,
			'dir' => $this->_db_dir,
		],$config);
		
		$this->set_db_dir($config['dir']);
		$this->set_extension($config['extension']);
		$this->set_encryption($config['encrypt']);
	}
	
	private function set_db_dir($dir){
		$this->_db_dir = $dir;
	}
	public function insert($table, $new_data){
		$this->_load_table($table);

		if(!empty($new_data)){
			$id = $this->get_unique_id();
			$this->db_cache[$table][$id] = $new_data;
			if($this->write_to_disk($table)){
				return $id;
			}
			return false;
		}
		return false;
	}
    
	public function get_unique_id($length=16){
        $characters = '0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ';
        $charactersLength = strlen($characters);
        $randomString = '';
        for ($i = 0; $i < $length; $i++) {
            $randomString .= $characters[random_int(0, $charactersLength - 1)];
        }
        return $randomString;
	}
	
	public function select($table, $condition = null){
		$this->_load_table($table);
		
		if(empty($this->db_cache[$table]))
			return $this->select_all($table);
		if (!$condition) {
			return $this->db_cache[$table];
		}
		if(is_array($condition)){
			$data = [];
			foreach($this->db_cache[$table] as $k => $v){
				foreach($condition as $condition_key => $condition_value){
					if(!isset($v[$condition_key]) || $v[$condition_key] != $condition_value){
						continue 2;
					}
				}
				$data[$k] = $v;
			}
			return $data;
		}else{
			return isset($this->db_cache[$table][$condition]) ? [$condition => $this->db_cache[$table][$condition]] : false;
		}
	}

	public function select_all($table){
		$this->_load_table($table);
		return $this->db_cache[$table];
	}

	private function write_to_disk($table){
		if(!isset($this->db_cache[$table])){
			return file_put_contents($this->get_table_path($table),'');
		}
		return file_put_contents($this->get_table_path($table),json_encode($this->db_cache[$table]));
	}
	public function delete($table, $id = null){
		$this->_load_table($table);

		if(!isset($id) || empty($id)){
			
		}else{
			if(isset($this->db_cache[$table][$id])){
				unset($this->db_cache[$table][$id]);
				return $this->write_to_disk($table);
			}
		}
		return false;
	}
	public function delete_all($table) {
		$this->set_table($table);
		unset($this->db_cache[$table]);
		return $this->write_to_disk($table);
	}
	public function update($table, array $data, $id){
		$this->_load_table($table);

		if(isset($this->db_cache[$table][$id])){
			$this->db_cache[$table][$id] = array_merge(
				$this->db_cache[$table][$id],
				$data
			);
			if($this->write_to_disk($table)){
				return $this->db_cache[$table];
			}else{
				return false;
			}
		}
		return false;
	}
	private function get_table_path($table) {
		if ($this->_check_table_dir()) {
			$filename = strtolower($table);
			return $this->get_db_dir() . $this->_get_hash($table) . '.' . $this->getExtension();
		}
	}
	private function get_db_dir(){
		return $this->_db_dir . '/';
	}
	private function _check_table_dir() {
		static $cache = null;
		if($cache !== null){
			return $cache;
		}
		if (!is_dir($this->get_db_dir()) && !mkdir($this->get_db_dir(), 0775, true)) {
			$cache = false;
			throw new Exception('Unable to create file directory ' . $this->get_db_dir());
		} elseif (!is_readable($this->get_db_dir()) || !is_writable($this->get_db_dir())) {
			if (!chmod($this->get_db_dir(), 0775)) {
				$cache = false;
				throw new Exception($this->get_db_dir() . ' must be readable and writeable');
			}
		}
		$cache = true;
		return true;
	}
	private function _get_hash($filename) {
		if($this->_encrypt)
			return md5($filename);
		return $filename;
	}
	private function set_table($name){
		if(!isset($this->db_cache[$name])){
			$this->db_cache[$name] = [];
		}
		$this->current_tablename = $name;
	}
	private function get_table($table) {
		return $this->_tablename;
	}
	private function _load_table($table) {
		if(!isset($this->db_cache[$table])){
			if(!is_file($this->get_table_path($table))){
				$this->db_cache[$table] = [];
			}else{
				$this->db_cache[$table] = json_decode(file_get_contents($this->get_table_path($table)),true);
			}
		}
		$this->current_tablename = $table;
		return $this->db_cache[$table];
	}
	private function set_extension($ext) {
		$this->_extension = $ext;
		return $this;
	}
	private function set_encryption($ext){
		$this->_encrypt = $ext;
		return $this;
	}
	private function getExtension() {
		return $this->_extension;
	}
}