<?php

//用户数据模型
class UsersModel extends ApiBaseModel {
	
	//添加账号
	public function add_account($type) {
		//写入数据库
		$this->password = md5($this->password);
		$time = time();
		$this->last_login_time = $time;
		$this->last_login_ip = get_client_ip();
		$this->create_time = $time;
		$this->update_time = $time;
		$this->type = $type;				//用户类型
		return $this->add();
	}
	
	
	//通过账号验证账号是否存在
	public function account_is_have ($account) {

		return $this->where(array('account'=>$account))->getField('id');
	}
	
	//获取账号数据
	public function get_user_info ($condition) {
		return $this->where($condition)->find();
	}
	
	public function get_account ($condition) {
		$con = array('is_del'=>0);
		array_add_to($con,$condition);
		return $this->where($con)->field('account')->find();
	}
	
	//修改密码
	public function modifi_user_password ($id,$password) {
		return $this->where(array('id'=>$id))->save(array('password'=>$password));
	}
	
	
	//更新登录信息
	public function up_login_info ($uid) {
		
		$time = time();
		$con['last_login_time'] = $time;
		$con['last_login_ip'] = get_client_ip();
		$con['login_count'] = array('exp','login_count+1');
		return $this->where(array('id'=>$uid))->save($con);

// 		$time = time();
// 		$this->last_login_time = $time;
// 		$this->last_login_ip = get_client_ip();
// 		$this->login_count = $this->login_count + 1; 
			
// 		$this->where(array('id'=>$uid))->save();
	
	}
	
	
	public function seek_all_data () {
		$data = $this->field('u.id,u.account,u.last_login_time,u.last_login_ip,u.type,u.status')
		->table($this->prefix.'users AS u')
		->where(array('u.is_del'=>0,'u.type'=>array('neq',0)))
		->select();
		parent::set_all_time($data, array('last_login_time'));
		return $data;
	}

	
	
	
	
	
}

?>
