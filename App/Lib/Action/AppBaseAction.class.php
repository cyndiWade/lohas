<?php

/**
 * 	项目---核心类
 *	 所有此项目分组的基础类，都必须继承此类
 */
class AppBaseAction extends GlobalParameterAction {
	
	/**
	 * 构造方法
	 */
	public function __construct() {
		//G('begin'); 							// 记录开始标记位（运行开始）
		
		//初始化数据库连接
		$this->db_init();	
		
		parent::__construct();

	}

	
	//初始化DB连接
	private function db_init() {
		foreach ($this->db as $key=>$val) {
			if (empty($val)) continue;
			$this->db[$key] = D($val);
		}
		
	}
	

	/**
	 * 短信发送类
	 * @param String $telephone  电话号码
	 * @param String $msg			短信内容
	 * @return Array  						$result[status]：Boole发送状态    $result[info]：ARRAY短信发送后的详细信息 	$result[msg]：String提示内容
	 */
// 	protected function send_shp ($telephone,$msg) {
// 		//执行发送短信
// 		import("@.Tool.SHP");	//SHP短信发送类
// 		$SHP = new SHP(C('SHP.NAME'),C('SHP.PWD'));			//账号信息
// 		$send = $SHP->send($telephone,$msg);		//执行发送
// 		return $send;
// 	}
	protected function send_shp ($telephone,$msg) {
		$shp_type = C('SHP.TYPE');
		$shp_name = C('SHP.NAME');
		$shp_password = C('SHP.PWD');
		switch ($shp_type) {
			case 'SHP' :
				import("@.Tool.SHP");				//SHP短信发送类
				$SHP = new SHP($shp_name,$shp_password);			//账号信息
				$send = $SHP->send($telephone,$msg);		//执行发送
				break;
			case 'RD_SHP'	 :
				import("@.Tool.RD_SHP");		//RD_SHP短信发送类
				$SHP = new RD_SHP($shp_name,$shp_password);			//账号信息
				$send = $SHP->send($telephone,$msg);		//执行发送
				break;
			default:
				exit('illegal operation！');	
		}
		return $send;
	}
	
	
	/**
	 * 统一数据返回
	 * @param unknown_type $status
	 * @param unknown_type $msg
	 * @param unknown_type $data
	 */
	protected function callback($status, $msg = 'Yes!',$data = array()) {
		$return = array(
				'status' => $status,
				'msg' => $msg,
				'data' => $data,
				'num' => count($data),
		);	
		
		header('Content-Type:application/json;charset=utf-8');
	//	header("Content-type: text/xml;charset=utf-8");
		//header('charset=utf-8');	
		//die(json_encode($return));
		exit(JSON($return));
	}
	

	
	/**
	 * 组合图片外部访问地址
	 * @param Array $arr								//要组合地址的数组
	 * @param String Or Array	 $field			//组合的字段key  如：pic 或  array('pic','head')
	 * @param String $dir_type						//目录类型  如：images/
	 */
	protected function public_file_dir (Array &$arr,$field,$dir_type) {
		$public_file_dir =  C('PUBLIC_VISIT.domain').C('PUBLIC_VISIT.dir').$dir_type;			//域名、文件目录
		//递归
		if (is_array($field)) {
			for ($i=0;$i<count($field);$i++) {
				self::public_file_dir($arr,$field[$i],$dir_type);
			}
		} else {
			foreach ($arr AS $key=>$val) {
				if (empty($arr[$key][$field])) continue;
				$arr[$key][$field] = $public_file_dir.$val[$field];
			}
		}
	}
	
	
	
	

	
}


?>