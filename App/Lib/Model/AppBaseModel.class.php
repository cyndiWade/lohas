<?php 

/**
 * 公共---基础模型
 */

class AppBaseModel extends Model {
	
	protected $prefix;		//表前缀
	
	public function __construct() {
		parent::__construct();
		
		$this->admin_base_init();
	}
	
	//初始话表前缀
	private function admin_base_init () {
		$this->prefix = C('DB_PREFIX');
	}

	//删除方法
	public  function del($condition) {
		return $this->where($condition)->data(array('status'=>-2))->save();
	}
	
	//逻辑删除
	public function delete_data ($condition) {
		return $this->where($condition)->data(array('is_del'=>-2))->save();
	}
	
	//获取所有数据 
	public function get_all_data ($field = '*') {
		return $this->field($field)->select();
	}
	
	//获取指定数据
	public function get_spe_data ($condition,$field = '*') {
		return $this->field($field)->where($condition)->select();
	}
	
	//获取一条数据
	public function get_one_data ($condition,$field = '*') {
		return $this->field($field)->where($condition)->find();
	}
	
	//修改一条数据
	public function save_one_data ($condition) {
		return $this->where($condition)->save();
	}
	
	
	/**
	 * 格式化日期
	 * @param Array $all			//数组
	 * @param Array $fields			//字段如：array('create_time','update_time');
	 */
	protected function set_all_time(&$all,$fields,$default = 'Y-m-d H:i:s') {
		if (empty($all)) return false;
		/* 多维数组 */
		if (count($all[0]) >=1)  {
			foreach ($all AS $key=>$val) {
				for ($i=0;$i<count($fields);$i++) {
					if (empty($all[$key][$fields[$i]])) continue;
					$all[$key][$fields[$i]] = date($default,$all[$key][$fields[$i]]);
				}
			}
		/* 一维数组 */	
		} else {
			for ($i=0;$i<count($fields);$i++) {
				if (empty($all[$fields[$i]])) continue;
				$all[$fields[$i]] = date($default,$all[$fields[$i]]);
			}
		}	
		
	}
	
	
	/**
	 * 字符长度限制
	 * @param Array $all				//
	 * @param Array $fields			//字段如：array('create_time','update_time');
	 */
	protected function set_str_len(&$all,$fields,$length) {
		if (empty($all)) return false;
		/* 多维数组 */
		if (count($all[0]) >=1)  {
			foreach ($all AS $key=>$val) {
				for ($i=0;$i<count($fields);$i++) {			
					if (mb_strlen($all[$key][$fields[$i]],'utf-8') >$length) {
						$all[$key][$fields[$i]] = mb_substr($all[$key][$fields[$i]],0,10,'utf-8').'...';
			
					}	
				}
			}
			/* 一维数组 */
		} else {
			for ($i=0;$i<count($fields);$i++) {
				$all[$fields[$i]] = mb_substr($all[$key][$fields[$i]],0,10,'utf-8').'...';
			}
		}
	}
	
	
	
	
}
?>