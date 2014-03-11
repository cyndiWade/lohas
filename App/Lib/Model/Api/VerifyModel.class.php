<?php

/**
 * 短信验证表模型
 */
class VerifyModel extends ApiBaseModel {
	
	public function __construct() {
		parent::__construct();
	}
	
	//查找短信验证码
	public function seek_verify_data ($telephone,$type) {
		$data =  $this->field('id,verify,expired')
		->where(array('telephone'=>$telephone,'type'=>$type,'status'=>0))
		->order('id DESC')
		->find();
		return $data;
	}	
	
	//修改验证码状态为已使用
	public function save_verify_status ($id) {
		return $this->where(array('id'=>$id))->data(array('status'=>1))->save();
	}
	
}

?>
