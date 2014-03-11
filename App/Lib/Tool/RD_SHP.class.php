<?php

/**
 * 荣大友信
 * 短信发送处理类
 * 网址：http://www.rdsms.net/
 * 接口文档地址：http://www.rdsms.net/view05.htm
 */

class RD_SHP { 
		
	private $name;		//账号名
	private $pwd;		//密码

	public function __construct($name,$pwd) {
		$this->name = $name;
		$this->pwd = $pwd;
	}
	
	/**
	 * 发送接口
	 * @param num(11) $phone		电话号码，多条用分号隔离;
	 * @param string $msg				短信消息
	 * @param INT $time				定时发送，格式：时间戳
	 */
	public function send($phone,$msg,$time='') {
		
		if (is_array($phone)) {
			$phone = implode(';',$phone);
		}
		
		if (!empty($time)) $time = date('yyyy-MM-dd HH:mm:ss',$time);
		
		
		$post_data = array();
		$post_data['username'] = $this->name;		//用户名
		$post_data['password'] = $this->pwd;			//密码
		$post_data['mobile'] = $phone;					//手机号，多个号码以分号分隔，如：13407100000;13407100001;13407100002
		$post_data['content'] = urlencode($msg."【车神集团】");	//内容，如为中文一定要使用一下urlencode函数
		$post_data['extcode'] = "";							//扩展号，可选
		$post_data['senddate'] = $time;					//发送时间，格式：yyyy-MM-dd HH:mm:ss，可选
		$post_data['batchID'] = "";								//批次号，可选
		$url='http://116.213.72.20/SMSHttpService/send.aspx';		//发送接口
		
		$o="";
		foreach ($post_data as $k=>$v)
		{
			$o.= "$k=".$v."&";
		}
		
		/* 执行发送 */
		$post_data=substr($o,0,-1);
		$this_header = array("content-type: application/x-www-form-urlencoded;charset=UTF-8");
		$ch = curl_init();
		curl_setopt($ch, CURLOPT_POST, 1);
		curl_setopt($ch, CURLOPT_HTTPHEADER,$this_header);
		curl_setopt($ch, CURLOPT_HEADER, 0);
		curl_setopt($ch, CURLOPT_URL,$url);
		curl_setopt($ch, CURLOPT_POSTFIELDS, $post_data);
		curl_setopt($ch, CURLOPT_RETURNTRANSFER, true);
		$result = curl_exec($ch);			//返回相应的标识，具体请参考我方提供的短信API文档
		curl_close($ch);
		
		//根据手册编写的结果。
		$prepare = array(
			-2 => '提交的号码中包含不符合格式的手机号码',
			-1 => '数据保存失败',
			0 => '成功',
			1001 => '短信用户名或密码错误',
			1002 => '余额不足',
			1003 => '参数错误',
		);
		
		if ($result == 0) {
			$return_result['status']  =  true;
			$return_result['info']['success'] = '成功！';		
			$return_result['msg'] = '短信发送成功！';
		} else {
			$return_result['status']  =  false;
			$return_result['info'] = $prepare[$result];
			$return_result['msg'] = $prepare[$result];
		}	
		return $return_result;
		
	}
	
}




?>