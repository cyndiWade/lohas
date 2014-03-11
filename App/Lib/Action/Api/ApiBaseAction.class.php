<?php

/**
 * Api接口--基础类
 */
class ApiBaseAction extends AppBaseAction {

	/**
	 * 数据表对象
	 * @var Array   访问如：$this->db['Verify']->where(id=10)->save();
	 */
	protected $db = array(

	);
	
	protected $Verify = array();		//需要验证的方法名

	protected $request;					//获取请求的数据
	

	
	/**
	 * 构造方法
	 */
	public function __construct() {
		$this->Init_Request();		//初始化数据		
		$this->Add_to_db();			//追加的表模型
		parent:: __construct();			//重写父类构造方法
	
		$this->Api_loading();			//加载	
		$this->Api_init();				//初始化
	}
	
	
	/**
	 * 初始化
	 */
	private function Init_Request () {
		$this->request['user_key'] = $this->_post('user_key');		//身份验证的user_key
		//$this->request['user_key'] = "UWRSbwgxBWsHNFVhAGUFYgUxA2gEaFUxAjxbO1E0CWRRbAY1BSBXMVdlUngNYVc0";
		$this->request['verify'] = $this->_post('verify');					//短信验证码
	}
	
	
	
	/**
	 * 追加数据库链接
	 */
	private function Add_to_db() {
		if (!empty($this->add_db)) {
			foreach ($this->add_db AS $key=>$val) {
				$this->db[$key] = $val;
			}
		}	
	}
	
	
	
	//记载RBAC权限控制类库
	private function Api_loading() {
		import("@.Tool.RBAC"); 				//权限控制类库
		/* 初始化数据 */
		$ApiConf = new stdClass();
	
		/* 数据表配置 */
		$ApiConf->table_prefix =  C('DB_PREFIX');
		$ApiConf->node_table = C('RBAC_NODE_TABLE');
		$ApiConf->group_table = C('RBAC_GROUP_TABLE');
		$ApiConf->group_node_table = C('RBAC_GROUP_NODE_TABLE');
		$ApiConf->group_user_table = C('RBAC_GROUP_USER_TABLE');
	
		/* 方法配置 */
		$ApiConf->group = GROUP_NAME;					//当前分组
		$Combination->module = MODULE_NAME;				//当前模块
		$ApiConf->action = ACTION_NAME;					//当前方法
		$ApiConf->not_auth_group = C('NOT_AUTH_GROUP');			//无需认证分组
		$ApiConf->not_auth_module = C('NOT_AUTH_MODULE');		//无需认证模块
		$ApiConf->not_auth_action = C('NOT_AUTH_ACTION');			//无需认证操作
	
		RBAC::init($ApiConf);		//初始化数据
	}
	
	
	//初始化用户数据
	private function Api_init() {
		
// 		$demo = array(
// 			'id'=>'2',
// 			'account'=>'user1',
// 			'type'=>'1',
// 		) ;
// 		 $this->oUser = (object) $demo;
		 
		//验证需要登录，有身份标识的模块
		if (in_array(ACTION_NAME,$this->Verify)) {
			if (empty($this->oUser)) {
				$this->deciphering_user_info();
			}
		}
		
		/* 身份标识验证验证 
		if (empty($this->oUser) && !in_array(MODULE_NAME,explode(',',C('NOT_AUTH_MODULE')))) {
			$this->deciphering_user_info();
		}*/
		
		 /* RBAC权限系统验证 */
		 if (C('USER_AUTH_ON') == true) {
		 
		 	/* 对于不是管理员的用户进行权限验证 */
		 	if (!in_array($this->oUser->account,explode(',',C('ADMIN_AUTH_KEY')))) {

		 		/* 权限验证 */
		 		$check_result = RBAC::check($this->oUser->id);

		 		if ($check_result['status'] == false) {
		 			parent::callback(C('STATUS_NOT_LOGIN'),$check_result['message']);
		 		}
		 	}
		 }
	}
	
	
	/**
	 * 解密客户端秘钥，获取用户数据
	 */
	private function deciphering_user_info() {
		//获取加密身份标示
		$identity_encryption = $this->request['user_key'];	
		
		//解密获取用户数据
		$decrypt = passport_decrypt($identity_encryption,C('UNLOCAKING_KEY'));	
		$user_info = explode(':',$decrypt);		
		$uid = $user_info[0];				//用户id
		$account = $user_info[1];		//用户账号
		$date = $user_info[2];			//账号时间

		//安全过滤
		if (count($user_info) < 3) $this->callback(C('STATUS_OTHER'),'身份验证失败');			
		if (countDays($date,date('Y-m-d'),1) >= 30 ) $this->callback(C('STATUS_NOT_LOGIN'),'登录已过期，请重新登录');		//钥匙过期时间为30天

		//去数据库获取用户数据
		$user_data = $this->db['Users']->field('id,account,nickname')->where(array('id'=>$uid))->find();

		if ($user_data ==  false || $account != $user_data['account']) {
			parent::callback(C('STATUS_NOT_DATA'),'此用户不存在，或被禁用');
		} else {
			$this->oUser = (object) $user_data;	
		}

	}
	

	/**
	 * 上传文件
	 * @param Array    $file  $_FILES['pic']	  上传的数组
	 * @param String   $type   上传文件类型    pic为图片 	
	 * @return Array	  上传成功返回文件保存信息，失败返回错误信息
	 */
	protected function upload_file($file,$type,$dir) {
		import('@.ORG.Util.UploadFile');				//引入上传类
		
		$upload = new UploadFile();
		$upload->maxSize  = 3145728 ;			// 设置附件上传大小
		$upload->allowExts  = array('jpg', 'gif', 'png', 'jpeg');		// 上传文件的(后缀)（留空为不限制），，
		//上传保存
		$upload->savePath =  $dir;					// 设置附件上传目录
		$upload->autoSub = true;					// 是否使用子目录保存上传文件
		$upload->subType = 'date';					// 子目录创建方式，默认为hash，可以设置为hash或者date日期格式的文件夹名
		$upload->saveRule =  'uniqid';				// 上传文件的保存规则，必须是一个无需任何参数的函数名
			
		//执行上传
		$execute = $upload->uploadOne($file);
		//执行上传操作
		if(!$execute) {						// 上传错误提示错误信息
			//$upload->getErrorMsg();
			return false;
		}else{	//上传成功 获取上传文件信息
			return $execute;
		}
	}
	
	
	
	/**
	 * 城市映射，通过城市名，获取城市id
	 * @param String $city_name		//市级城市名
	 */
	protected function get_city_id ($city_name) {
		$City = D('City');		//店铺模型表
		$all_city = $City->get_city_cache();			//读取城市缓存数据
		foreach ($all_city AS $val) {			//获取匹配后的城市id
			if (find_string($val['name'],$city_name)) {
				$city = $val['id'];
				break;
			}
		}
		return $city;
	}
	
	
	
	/**
	 * 短信验证模块
	 * @param String $telephone		//验证的手机号码
	 * @param Number $type				//验证类型：1为注册验证
	 */
	protected function check_verify ($telephone,$type) {
	
	//	$Verify = D('Verify');							//短信表
		$Verify = $this->db['Verify'];		
		$verify_code = $this->request['verify'];		//短信验证码
		
		$shp_info = $Verify->seek_verify_data($telephone,$type);

		//手机验证码验证
		if (empty($shp_info)) {
			self::callback(C('STATUS_NOT_DATA'),'验证码不存在');
		} elseif ($verify_code != $shp_info['verify']) {
			self::callback(C('STATUS_OTHER'),'验证码错误');
		} elseif ($shp_info['expired'] - time() < 0 ) {
			self::callback(C('STATUS_OTHER'),'验证码已过期');
		}
		//把验证码状态变成已使用
		$Verify->save_verify_status($shp_info['id']);
	}
	
	/**
	 * 记录订单操作历史
	 * @param INT $order_id
	 * @param STRING $content
	 */
	protected function order_history ($order_id,$content) {
		return $this->db['OrderHistory']->add_order_history($order_id,0,$content);	//表示用户自己
	}
	
	
	
	
}


?>