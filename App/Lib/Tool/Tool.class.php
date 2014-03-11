<?php  //工具类

class Tool {
		
		//弹窗跳转
		static public function alertLocation ($_info,$_url) {
			if (!empty($_info)) {
				echo "<script type='text/javascript'>alert('$_info');location.href='$_url';</script>";
				exit();	
			} else {
				header('Location:'.$_url);			
				exit();
			}		
		}
		
		//弹窗返回
		static public function alertBack($_info) {
			echo "<script type='text/javascript'>alert('$_info');history.back();</script>";
			exit();
		}
		
		//弹窗关闭
		static public function alertClose($_info) {
			echo "<script type='text/javascript'>alert('$_info');close();</script>";
			exit();
		}
		

		
		//写入数据库，对SQL语句中出现的，特殊字符过滤。如出现("\')等字符，在前面自动加上\。
			//写入数据时的转换
		static public function mysqlString($data) {
			return !GPC ? addslashes($data) : $data;
//			if (!GPC) {//如果PHP内置，自动转义没有打开.
//				return mysql_escape_string($_date);//返回转义后的字符串
//			} else {
//				return $_date;
//			}
			//如果是Linux下，把mysql_escape_string()函数替换为addslashes();	
		}		

		//把包含了html的字符串转换为纯字符串实体。过滤的字符有(&\"\'\<\>)。
		static public function htmlString ($_date) {
			if (is_array($_date)) {
				foreach ($_date as $_key => $_value) {
					$_string[$_key] =  self::htmlString($_value);
				}
			} else if (is_object($_date)) {
				foreach ($_date as $_key => $_value) {
					$_string->$_key =  self::htmlString($_value);	
				}
			} else {
				$_string = htmlspecialchars($_date);
			}
			return $_string;//传入的是对象，返回对象、是数组，返回数组、是字符串则返回字符串
		}
		//把包含了被htmlspecialchars()转义过的字符串，还原为字符串加html
		static public function unHtml($_str) {
			return htmlspecialchars_decode($_str);
		}
		
		
		/*HTML显示长度限制
		 * $_object 		  对象数组
		 * $_field 	 		  对象数组字段
		 * $_length		  截取的长度
		 * $_encoding   截取字符编码.如 'utf-8'
		 * return 			 截取完毕的数组
		 */
		static public function subStr(&$_object,$_field,$_length,$_encoding) {
			if ($_object) {//如果对象数组存在值
				if (is_array($_object)) {
					foreach ($_object as $key => $value) {
						if (mb_strlen($value->$_field,$_encoding) > $_length) {	//如果对象数组中的字段长度，大于规定值
						//截取规定字段到指定长度
							$value->$_field = mb_substr($value->$_field,0,$_length,$_encoding).'...';	
						}
					}	
				} else {
					if (mb_strlen($_object,$_encoding) > $_length) {
						//$_object = mb_substr($_object,0,$_length,$_encoding);
						return mb_substr($_object,0,$_length,$_encoding).'...';
					} else {
						return mb_substr($_object,0,$_length,$_encoding);
					}		
				}				
			}
			//return $_object;//返回对象数组	
		}
		
		
		/*	对象数组转换成字符串,并且去掉最后的,号
		 * 	$_object  数组对象
		 * 	$_fild		数组对象其中某一个字段
		 * return 字符串
		 */
		static public function objArrOfstr ($_object,$_fild) {
			if ($_object) {	//如果有值
				foreach ($_object as $_value) {
					$_html .= $_value->$_fild.',';
				}
			}
			return substr($_html,0,strlen($_html)-1) ;//去掉最后的逗号
		}
		
		
		/*获取当前运行的脚本文件名(没有后缀)，用当前文件名生成一个新的文件类型
		 * $_name //传入需要生成的文件类型。如：.tpl
		 * return 	新的文件类型
		*/
		static public function UrlName($_name = null) {
			$_str  = explode('/',$_SERVER['SCRIPT_NAME']);//获取当前运行页面的地址，并且分割成数组
			$_num =  $_str[count($_str)-1];//获取数组最后一位的值(文件名)
			$_str = explode('.',$_num);		//把文件名分割成数组
			return $_str[0].$_name;			//返回规定的文件名
			/*方法二:
			$_url = basename(__file__);	//获取当前路径文件名部分
	 		$_array = explode('.',$_url);	//分割字符串为数组
			return $_array[0].$_name;		//重组文件名
			*/
		}
		
	/*	程序执行耗时
	 * 文件头部记录起始时间，文件尾部记录当前时间，当前时间减去起始时间，就是文件执行耗时。
	 * echo  round(Tool::_microtime() - STARTTIME,4).'秒';
	 */
		static public function _microtime() {
			$_mtime = explode(' ',microtime());
			return $_mtime[1] + $_mtime[0];
		}		

		
	/*	日期转换
	 * 把类似2012-8-12 12:10:57的日期 ， 转换为时间戳，把时间戳转换为月和日
	 * $_object	数组对象			
	 * $_type		需要需要转换的日期格式。如:y-m
	 * $date		对象数组中的字段名			如：date
	 */	
		static public function SetDate($_object,$_type,$_file) {
			if ($_object) {//如果日期存在
				if (is_array($_object)) {//如果是数组
					foreach ($_object as $value) {
						$value->$_file = date($_type,strtotime($value->$_file));
					}
				} else {//如果不是数组，是字符串
					return date($_type,strtotime($_object));
				}
			}
		}
		
		
		
		/**一、删除目录和该目录下的所有文件
		 * $dirname 文件目录 如："/lamp/apache/htdocs/CMS/uploads/20120917"
		 * 	return 文件目录是否删除成功的布尔值
		 */
		static function deleteDir($dirname) {		
			if (!is_dir($dirname)) return false;	//如果不是目录退出，不执行了
			if (!$handle = opendir($dirname)) return false;//打开一个目录
				//可以用sizeof()或者count()计算数组数量，来获取目录下文件个数
				//readdir(目录句柄) 		返回目录中的文件和文件名.	return string字符串形式
				//scandir(目录)				返回目录中的文件和文件名. return array  数组形式									
				while (($_file = readdir($handle)) != false) { //目录不是空则，列出目录中的所有文件
					if ($_file != '.' && $_file !='..' ) {
				  //if ($_file == '.' || $_file== '..') continue;//如果目录中出现.或者..则跳出这条循环	
						$_dir = $dirname.'/'.$_file; 
						is_dir($_dir) ? self::deleteDir($_dir) : unlink($_dir);//递归
					}
				} 
			closedir($handle);			//打开目录要关闭目录
			return rmdir($dirname);//删除目录，返回布尔值
		}
		/*	二、删除指定目录下的所有文件，保留目录
		 * 	$_dirName  目录路径
		 * 	return 删除文件是否成功  布尔值
		 */
		static function deleteUrlFile($_dirName) {
			if (!is_dir($_dirName)) return false;		//是不是正确路径
			if (!$_dir = opendir($_dirName)) return false;	//打开目录
			while (($_file = readdir($_dir)) != false) {			//目录不是空则，列出目录中的所有文件
				if ($_file == '.' || $_file == '..') continue;			//跳出此循环
				unlink($_dirName.'/'.$_file);							//删除目录中所有文件
			}
			closedir($_dir);
			return true;
		}
		/*三、删除一个文件
		 * $fileUrl 文件路径  如:/lamp/apache/htdocs/CMS/uploads/20120917/20120917203535645.jpg
		 * return 删除文件是否成功  布尔值
		 */
		static function deleteFile($_fileUrl) {
			if (!file_exists($_fileUrl)) return false;
			return unlink($_fileUrl);//删除文件，返回布尔值
		}
		
		
		
		
		//退出，清除SESSION
		static public function UnSession () {
			if (session_start()) {
				session_destroy();
			}
		}

}



		
		
	

?>