<?php

class Validate { //表单验证
		
	//是否为空
	static public function checkNull ($_data) {
		return trim($_data) == '';
	}
			
	//数字验证
	static public function checkNum ($_data) {
		return is_numeric($_data);
	}

	//账号验证
	static public function checkAccount($string) {								
		$check1 = preg_match("/^[A-Za-z][\w]{4,30}$/", $string);						//普通账号验证
		$check2 = preg_match("/^([\w\.\-]+)\@([\w]+)\.(com|cn)$/u", $string);	//邮箱验证

		if ($check1 || $check2) {
			return true;
		} else {
			return false;
		}		
	}
	
	//电话号码验证
	static public function checkPhone($string) {
		return preg_match("/^1[358]\d{9}$/", $string);
	}
	
	
	//长度是否合法
	static public function checkLength ($_data,$_length,$_flag) {
		if ($_flag == 'min') { //允许最小字符
			if (mb_strlen(trim($_data),'utf-8') <  $_length) return true;//字符串长度小于
			return false;
		} else if ($_flag == 'max') {//允许最大字符
			if (mb_strlen(trim($_data),'utf-8') >  $_length) return true;//字符串长度大于
			return false;
		} else if ($_flag == 'equals') {
			if (mb_strlen(trim($_data),'utf-8') != $_length) return true;
			return false;
		} else {//字符传值出错

		}
		
	}
			
	//二个提交的数据是否一致
	static public function checkEquals ($_data,$_otherdate) {
		if (trim($_data) == trim($_otherdate)) {
			return true;
		} else {
			return false;
		}

	}
			
	static public function checkemail ($_data) {
		$_zc = '/^[\w\-\.]+@[\w\-\.]+(\.\w+)+$/';
		return preg_match($_zc,$_data);

	}
			
		
	//账号验证
	static public function check_string_num($string) {
		$check = preg_match("/^[\w]+$/", $string);						//普通账号验证
		if ($check) {
			return true;
		} else {
			return false;
		}
	}
	
	/**
	 * 验证
	 * @param String $start		
	 * @param String $over
	 * @param Int $type		true日期：2013-10-15    false时间戳
	 */
	static public function count_days ($start,$over,$type = true) {	//传入时间戳、或者字符类型日期
		if ($type == true) {	
			//转换为时间戳
			$d1=strtotime($start);
			$d2=strtotime($over);
			//计算二个时间戳之差,获取相差天数
			$Days = round(($d2 - $d1)/3600/24);	
		} else {
			$Days = round(($over - $start)/3600/24);
		}
		return $Days;
	}
	

	/**
 	 * 验证 开始日期 是否大于 结束日期
	 * @param String $start_date		日期，如2010-10-12
	 * @param String $over_date		日期，如2010-10-24
	 * @return boolean						
	 */
	public function check_date_differ ($start_date,$over_date) {

		if (strtotime($start_date) > strtotime($over_date)) {
			return true;
		} else {
			return false;
		}

	}

	
}




?>