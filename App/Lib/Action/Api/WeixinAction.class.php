<?php 
ini_set('display_errors',1);
error_reporting(E_ALL);
//echo __FILE__;/web/www/ftp/tjr/zun/App/Lib/Action/Api/
define("TOKEN", "rikee");
class WeixinAction extends AppBaseAction{
	
  //初始化数据库连接
	 protected  $db = array(
		'Hotel'=>'Hotel',
	    'HotelRoom'    => 'HotelRoom',
	    'RoomSchedule' => 'RoomSchedule',
        'HotelOrder'   => 'HotelOrder',
	    'UsersHotel'   => 'UsersHotel',
	    'OrderState'   => 'OrderState',
		'RoomPutaway'  => 'RoomPutaway',
		'WxUser'       => 'WxUser',
		'Coupon'       => 'Coupon'
		
	 );
	  

	   public function index(){
		  //$this->valid();
		  //exit;
	      $OrderState = $this->db['OrderState'];
	      $OrderState->del_data();
		  $this->responseMsg();
	   }
/*
*==========================================================
* 响应类型
*==========================================================
*/  
	public function responseMsg()
	{
		$postStr = $GLOBALS["HTTP_RAW_POST_DATA"];
		if (!empty($postStr)){
			$postObj = simplexml_load_string($postStr, 'SimpleXMLElement', LIBXML_NOCDATA);
			$RX_TYPE = trim($postObj->MsgType);
			$user_code = $postObj->FromUserName;
			$WxUser = $this->db['WxUser'];
            $WxUser->The_existence_of_wxuser($user_code);  //是否关注

			$phone = $WxUser->The_existence_of_phone($user_code); //是否输入了手机号

			$text = empty($postObj->Content ) ? $postObj->Recognition : $postObj->Content ;
            $is_tel = is_phone("$text");
			if(empty($phone) and empty($is_tel) ){
			  $contentStr = '请输入手机号。';
			  $resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
			  die($resultStr);
			}elseif(!empty($is_tel)){
              $WxUser->where(array('wxid'=>"$user_code"))->save(array('phone'=>"$text"));
			  $contentStr = '验证成功';
              $resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
			  die($resultStr);
			  
			}
			switch ($RX_TYPE)
			{
				case "text":
				case "voice":
				    $OrderState = $this->db['OrderState'];
					$step = $OrderState->get_step($user_code);
				    $resultStr = $this->step($postObj,$step);
					break;
				case "image":
					$resultStr = $this->receiveText($postObj);
					break;
				case "location":
					//$resultStr = $this->receiveText($postObj);
					break;
				case "video":
					$resultStr = $this->receiveText($postObj);
					break;
				case "link":
					$resultStr = $this->receiveText($postObj);
					break;
				case "event":
					$resultStr = $this->receiveEvent($postObj);
					break;
				default:
					$resultStr = "unknow msg type: ".$RX_TYPE;
					break;
			}
			echo $resultStr;
		}else {
			echo "";
			exit;
		}
	}
/*
*==========================================================
* 响应类型
*==========================================================
*/

/*
*==========================================================
* 处理事件的方法  
*==========================================================
*/ 
	private function receiveEvent($object)
	{
	     $OrderState = $this->db['OrderState'];
		 $HotelOrder = $this->db['HotelOrder'];
         $Hotel      = $this->db['Hotel'];
		 $HotelRoom  = $this->db['HotelRoom'];
		 $WxUser     = $this->db['WxUser'];
		 $UsersHotel = $this->db['UsersHotel'];
		 $Coupon     = $this->db['Coupon'];
		 $user_code  = $object->FromUserName;
			$contentStr = "";
			switch ($object->Event)
			{
				case "subscribe":
					$contentStr = "欢迎关注尊旅会公众号";
					break;
				case "unsubscribe":
					$contentStr = "";
				    $WxUser->unsubscribe($user_code);
					
					break;
				case "CLICK":
					switch ($object->EventKey)
					{
						case 'menu_1_1':
							$OrderState->del_data_user($user_code);
							$contentStr =  '请用文字或语音录入您下榻酒店的城市。';
						    $resultStr = $this->transmitText($object, $contentStr);
							break;
						case 'menu_1_2':
							$contentStr ="客服电话:400-6096-906。\n 在线时间为8点~22点，客服人员将一对一为您服务。";
						    $resultStr = $this->transmitText($object, $contentStr);
							break;
						case 'menu_1_3':
							//每日特惠
							$arr_item = $Hotel->get_hotel_p();
							if(count($arr_item)>0){
						       $resultStr = $this->transmitNews($object, $arr_item, $flag = 0);
							}else{
                                $contentStr ="今天没有特惠";
						        $resultStr = $this->transmitText($object, $contentStr);
							}
							break;
						case 'menu_2_1':
                            $arr_item = $HotelOrder->get_order($user_code);
						    if(count($arr_item)>0){
						       $resultStr = $this->transmitNews($object, $arr_item, $flag = 0);
							}else{
                                $contentStr ="您还没有订单";
						        $resultStr = $this->transmitText($object, $contentStr);
							}
							break;
						case 'menu_2_2':
						case 'menu_2_3':
						case 'menu_2_4':
							$contentStr ="敬请期待......";
						    $resultStr = $this->transmitText($object, $contentStr);
							//特惠商品
							break;
						case 'menu_3_1':
							//特惠商品
						    $HotelOrder->get_order($user_code);
							break;
						case 'menu_3_2':
							//1美食
						    $arr_item = $Coupon->get_coupon(1);
							if(count($arr_item)>0){
						       $resultStr = $this->transmitNews($object, $arr_item, $flag = 0);
							}else{
                                $contentStr ="没有此优惠券";
						        $resultStr = $this->transmitText($object, $contentStr);
							}
							break;
						case 'menu_3_3':
							//2旅游
						    $arr_item = $Coupon->get_coupon(2);
							if(count($arr_item)>0){
						       $resultStr = $this->transmitNews($object, $arr_item, $flag = 0);
							}else{
                                $contentStr ="没有此优惠券";
						        $resultStr = $this->transmitText($object, $contentStr);
							}
							break;
						case 'menu_3_4':
							//3购物
						    $arr_item = $Coupon->get_coupon(3);
							if(count($arr_item)>0){
						       $resultStr = $this->transmitNews($object, $arr_item, $flag = 0);
							}else{
                                $contentStr ="没有此优惠券";
						        $resultStr = $this->transmitText($object, $contentStr);
							}
							break;
						case 'menu_3_5':
							//4娱乐
						    $arr_item = $Coupon->get_coupon(4);
							if(count($arr_item)>0){
						       $resultStr = $this->transmitNews($object, $arr_item, $flag = 0);
							}else{
                                $contentStr ="没有此优惠券";
						        $resultStr = $this->transmitText($object, $contentStr);
							}
							break;
							//我的优惠券
						case 'menu_3_6': 
							$arr_item = $Coupon->get_user_coupon($user_code);
							if(count($arr_item)>0){
						       $resultStr = $this->transmitNews($object, $arr_item, $flag = 0);
							}else{
								//$Coupon->getLastSql().
                                $contentStr = "您还没有优惠券";
						        $resultStr = $this->transmitText($object, $contentStr);
							}
							
							break;
							
						default:
							$resultStr = "你点击了菜单: ".$object->EventKey;
							break;
					}
					break;
			    case "LOCATION" :
					break;
				default:
					$resultStr = "receive a new event: ".$object->Event;
					break;
			}
			//tolog('/web/www/ftp/tjr/wxadmin/App/Lib/Action/Api/a.txt',$resultStr);
			return $resultStr;
	}
/*
*==========================================================
* 处理事件的方法  
*==========================================================
*/ 


/*
*===========================================================
* 文本的xml
*文本消息的处理xml transmitText($object, $content, $flag = 0)
*图文消息处理xml   transmitNews($object, $arr_item, $flag = 0)
*音乐处理xml       transmitMusic($object, $musicArray, $flag = 0)
*===========================================================
*/
	//文本消息的处理xml
	private function transmitText($object, $content, $flag = 0)
	{
			$textTpl = "<xml>
			<ToUserName><![CDATA[%s]]></ToUserName>
			<FromUserName><![CDATA[%s]]></FromUserName>
			<CreateTime>%s</CreateTime>
			<MsgType><![CDATA[text]]></MsgType>
			<Content><![CDATA[%s]]></Content>
			<FuncFlag>%s</FuncFlag>
			</xml>";
			$resultStr = sprintf($textTpl, $object->FromUserName, $object->ToUserName, time(), $content, $flag);
			return $resultStr;
	}
	//图文消息处理xml
	private function transmitNews($object, $arr_item, $flag = 0)
	{
			if(!is_array($arr_item))
				return;

			$itemTpl = "<item>
			<Title><![CDATA[%s]]></Title>
			<Description><![CDATA[%s]]></Description>
			<PicUrl><![CDATA[%s]]></PicUrl>
			<Url><![CDATA[%s]]></Url>
			</item>";
			$item_str = "";
			foreach ($arr_item as $item)
				$item_str .= sprintf($itemTpl, $item['Title'], $item['Description'], $item['Picurl'], $item['Url'].'/user_code/'.$object->FromUserName);

			$newsTpl = "<xml>
			<ToUserName><![CDATA[%s]]></ToUserName>
			<FromUserName><![CDATA[%s]]></FromUserName>
			<CreateTime>%s</CreateTime>
			<MsgType><![CDATA[news]]></MsgType>
			<ArticleCount>%s</ArticleCount>
			<Articles>
			$item_str</Articles>
			<FuncFlag>%s</FuncFlag>
			</xml>";

			$resultStr = sprintf($newsTpl, $object->FromUserName, $object->ToUserName, time(), count($arr_item), $flag);
			return $resultStr;
	}

/*
*===========================================================
* 文本的xml
*===========================================================
*/






// 文本消息
private function receiveText($object)
{
        $funcFlag = 0;
        $contentStr = "你发送的是文本，内容为：".$object->Content;
        $resultStr = $this->transmitText($object, $contentStr, $funcFlag);
        return $resultStr;
}

   //判断流程

   public function step($postObj,$step){
        
		 $OrderState = $this->db['OrderState'];
		 $HotelOrder = $this->db['HotelOrder'];
         $Hotel = $this->db['Hotel'];
		 $HotelRoom = $this->db['HotelRoom'];
		 $WxUser    = $this->db['WxUser'];
		 $UsersHotel = $this->db['UsersHotel'];
		 $text = $postObj->Content;
		 $user_code = $postObj->FromUserName;
		 if(empty($text)){
		   $text = $postObj->Recognition ;
		 }
		 //tolog('/web/www/ftp/tjr/wxadmin/App/Lib/Action/Api/a.txt',$text);
		 //tolog('/web/www/ftp/tjr/wxadmin/App/Lib/Action/Api/a.txt',$step);
		 $T= 60*30;
		 if(in_array("$text",$this->city)){
			$OrderState->del_data_user($user_code);
			$step = 0;
		 }
         switch($step){
		 
		     case 0 :
				 //城市名
			    if(!in_array("$text",$this->city)){
					$contentStr = '您输入的不是城市名称。';
					$resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
					die($resultStr);
				}
				    $data = array('user_code'=>"$user_code",'hotel_add'=>"$text",'step'=>$step+1,'endtime'=>time()+$T);
					$arr_item = $Hotel->get_all_hotel("$text");	
					if(!$arr_item){
                        $contentStr = $text.'该城市是没有酒店信息。';
						$resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
						die($resultStr);
					  
					}
					$resultStr = $this->transmitNews($postObj, $arr_item, $flag = 0);
					
				 break;
			 case 1 :	
				 //该城市下的酒店
				 $arr_item = $Hotel->get_Hotel("$text");
				 if(count($arr_item['list'])<=0){

                        $contentStr = '没有该 '.$text.' 酒店信息。';
						$resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
						die($resultStr);
					  
				 }

				 $data = array('step'=>$step+1,'hotel_name'=>$arr_item['hotel_name'],'hotel_id'=>$arr_item['hotel_id'],'endtime'=>time()+$T);
				 $resultStr = $this->transmitNews($postObj, $arr_item['list'], $flag = 0);
				 break;
			 case 2 :
				 //选择房型
			     $PAY_TYPE = C('PAY_TYPE');
                 $hotel_id = $OrderState->get_hotel_id($user_code);
                 preg_match('/预付/',$text,$arr);
				 preg_match('/现付/',$text,$arr2);
				 if($arr2){
					$text = str_replace('现付','',$text);
                    $pay_type = 2;
				 }
				 if($arr){
					$text = str_replace('预付','',$text);
                    $pay_type = 1;
				 }
				 if(empty($arr2) and empty($arr) ){
				     $pay_type = 1; 
				 }
				 
                 $arr_item = $HotelRoom->get_room_type("$text",$hotel_id,$pay_type);

				 if(count($arr_item)<=2){

                        $contentStr = '输入有误或者没有该房型,您输入的为 ：'.$text;
						$resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
						die($resultStr);
					  
				 }
				 $data = array('step'=>$step+1,'room_id'=>$arr_item['room_id'],'room_name'=>$arr_item['title'],'room_price'=>$arr_item['price'],'pay_type'=>$arr_item['pay_type'],'endtime'=>time()+$T);
				 $contentStr = '您选了：'.$arr_item['title']." 房型 \n".'价格为 ：'.$arr_item['price'] .'元 '."\n".'付款方式为 : '.$PAY_TYPE[$arr_item['pay_type']]['explain']."\n".'请输入入住时间。如 (今天 ,明天 后天)';
				 $resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
				 break;
			 case 3 :
				 // 入住时间
			     $time =  getTime("$text");
				 if(empty($time)){

				        $contentStr = '你输入的时间有误 。您输入的是:'.$text;
						$resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
						die($resultStr);
				 }else{
					 //判断时间的正确性 入住时间必须大于今天
					 $daytime = strtotime(date('Y-m-d',time())); //当天的时间戳

					 if($time<$daytime){
                        $contentStr = '你输入的时间已过去了。您输入的是:'.$text;
						$resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
						die($resultStr);
					 }

				 
				 
				 }
				 $data = array('step'=>$step+1,'endtime'=>time()+$T,'startrz'=>$time);
				 $contentStr = '您的入住时间 ：'.date('Y-m-d',$time)."\n".'请输入离开时间。';
                 $resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
				 break;
			 case 4 :
				 // 离店时间
			     $time =  getTime("$text");
				 if(empty($time)){

				        $contentStr = '你输入的时间有误 。您输入的是:'.$text;
						$resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
						die($resultStr);
				 }else{
				    //离店时间大于入住时间
                    $in_time = $OrderState->get_in_time($user_code); // 入住时间
					
					if($time <= $in_time){

					    $contentStr = '你输入的时间有误,应该大于入住时间。您输入的是:'.$text;
						$resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
						die($resultStr);
					  
					}
				 
				 }
				 $data = array('step'=>$step+1,'endtime'=>time()+$T,'endlikai'=>$time);
				 $contentStr = '您的离开时间 ：'.date('Y-m-d',$time)."\n".'请输入确认 或付款提交订单。';
                 $resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);

				 break;
		     case 5 :
				 // 确认订单
                 if($text=='确认' or $text =='付款'){

				    $data =$OrderState->get_order_info($user_code);
					$arr = $data['data'];
					$phone = $WxUser->The_existence_of_phone($user_code);					
					$user_id = $UsersHotel->get_uid($arr['hotel_id']);
					$user_id = empty($user_id)? 0 : $user_id;
                    $total = $arr['total'];
					$in_date   = $arr['startrz'];
					$out_date  = $arr['endlikai'];
                    $pay_type  = $arr['pay_type'];
                    $order = array(
						'order_sn'=>date('Ymd',time()).time(),
						'order_time' =>time(),
						'user_id'=>$user_id,
						'user_code'  =>"$user_code",
						'hotel_id'   =>$arr['hotel_id'],
						'hotel_room_id'=>$arr['room_id'],
						'phone'        =>$phone,
						'total_price'  =>$total,
						'room_num'     =>1,
						'in_date'      =>$in_date,
						'out_date'     =>$out_date,												
						'order_status' =>0,
						'dispose_status'=>0,
						'is_from'      =>2,
						'order_type'   =>$pay_type,
						'is_pay'       =>0,
						'is_del'       =>0
						);
					$HotelOrder->data($order)->add();

					$contentStr = $data['str'];
                    $OrderState->del_data_user($user_code);
					
			     }else{
				    $contentStr = '输入错误，您输入的是：'.$text;
                    $resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
				 }
				 $resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
				 
				 break;
			 default :
				 //$resultStr = $this->transmitText($postObj, $contentStr, $funcFlag);
				 break;
		 
		 }
		 if($step == 0){
              $OrderState->add_step($data);
			
		 }else{
		      $OrderState->where(array('user_code'=>"$user_code"))->save($data);
			 
		 }
         
tolog('/web/www/ftp/tjr/wxadmin/App/Lib/Action/Api/a.txt',$resultStr);
		 return $resultStr;
   
   
   
   
   }
   
   public function test(){
   
          $OrderState = $this->db['OrderState'];
          $RoomPutaway = $this->db['RoomPutaway'];
		  $Hotel = $this->db['Hotel'];
		  $HotelOrder  = $this->db['HotelOrder'];
		  $HotelRoom = $this->db['HotelRoom'];
		  $WxUser    = $this->db['WxUser'];
		  $UsersHotel = $this->db['UsersHotel'];
		  $Coupon     = $this->db['Coupon'];
		  $Hotel     = $this->db['Hotel'];
      
		 $user_code = 'o_kNsuAeyDl9qX3L1KapcipFN3ik';
		 //$data = $Coupon->get_user_coupon($user_code);
		 $data =  $Hotel->get_hotel_p();
		  echo '<pre>';print_R($data);echo '</pre>';
		 
          
   
   }

   public function valid()
    {
        $echoStr = $_GET["echostr"];

        //valid signature , option
        if($this->checkSignature()){
        	echo $echoStr;
        	exit;
        }
    }

	private function checkSignature()
	{
        $signature = $_GET["signature"];
        $timestamp = $_GET["timestamp"];
        $nonce = $_GET["nonce"];	
        		
		$token = TOKEN;
		$token = 'rikee';
		$tmpArr = array($token, $timestamp, $nonce);
		sort($tmpArr);
		$tmpStr = implode( $tmpArr );
		$tmpStr = sha1( $tmpStr );
		
		if( $tmpStr == $signature ){
			return true;
		}else{
			return false;
		}
	}

   public  $city = array('安庆','蚌埠','巢湖','池州','滁州','阜阳','淮北','淮南','黄山','六安','马鞍山','宿州','铜陵','芜湖','宣城','亳州','北京','福州','龙岩','南平','宁德','莆田','泉州','三明','厦门','漳州','兰州','白银','定西','甘南','嘉峪关','金昌','酒泉','临夏','陇南','平凉','庆阳','天水','武威','张掖','广州','深圳','潮州','东莞','佛山','河源','惠州','江门','揭阳','茂名','梅州','清远','汕头','汕尾','韶关','阳江','云浮','湛江','肇庆','中山','珠海','南宁','桂林','百色','北海','崇左','防城港','贵港','河池','贺州','来宾','柳州','钦州','梧州','玉林','贵阳','安顺','毕节','六盘水','黔东南','黔南','黔西南','铜仁','遵义','海口','三亚','白沙','保亭','昌江','澄迈县','定安县','东方','乐东','临高县','陵水','琼海','琼中','屯昌县','万宁','文昌','五指山','儋州','石家庄','保定','沧州','承德','邯郸','衡水','廊坊','秦皇岛','唐山','邢台','张家口','郑州','洛阳','开封','安阳','鹤壁','济源','焦作','南阳','平顶山','三门峡','商丘','新乡','信阳','许昌','周口','驻马店','漯河','濮阳','哈尔滨','大庆','大兴安岭','鹤岗','黑河','鸡西','佳木斯','牡丹江','七台河','齐齐哈尔','双鸭山','绥化','伊春','武汉','仙桃','鄂州','黄冈','黄石','荆门','荆州','潜江','神农架林区','十堰','随州','天门','咸宁','襄樊','孝感','宜昌','恩施','长沙','张家界','常德','郴州','衡阳','怀化','娄底','邵阳','湘潭','湘西','益阳','永州','岳阳','株洲','长春','吉林','白城','白山','辽源','四平','松原','通化','延边','南京','苏州','无锡','常州','淮安','连云港','南通','宿迁','泰州','徐州','盐城','扬州','镇江','南昌','抚州','赣州','吉安','景德镇','九江','萍乡','上饶','新余','宜春','鹰潭','沈阳','大连','鞍山','本溪','朝阳','丹东','抚顺','阜新','葫芦岛','锦州','辽阳','盘锦','铁岭','营口','呼和浩特','阿拉善盟','巴彦淖尔盟','包头','赤峰','鄂尔多斯','呼伦贝尔','通辽','乌海','乌兰察布市','锡林郭勒盟','兴安盟','银川','固原','石嘴山','吴忠','中卫','西宁','果洛','海北','海东','海南','海西','黄南','玉树','济南','青岛','滨州','德州','东营','菏泽','济宁','莱芜','聊城','临沂','日照','泰安','威海','潍坊','烟台','枣庄','淄博','太原','长治','大同','晋城','晋中','临汾','吕梁','朔州','忻州','阳泉','运城','西安','安康','宝鸡','汉中','商洛','铜川','渭南','咸阳','延安','榆林','上海','成都','绵阳','阿坝','巴中','达州','德阳','甘孜','广安','广元','乐山','凉山','眉山','南充','内江','攀枝花','遂宁','雅安','宜宾','资阳','自贡','泸州','天津','拉萨','阿里','昌都','林芝','那曲','日喀则','山南','乌鲁木齐','阿克苏','阿拉尔','巴音郭楞','博尔塔拉','昌吉','哈密','和田','喀什','克拉玛依','克孜勒苏','石河子','图木舒克','吐鲁番','五家渠','伊犁','昆明','怒江','普洱','丽江','保山','楚雄','大理','德宏','迪庆','红河','临沧','曲靖','文山','西双版纳','玉溪','昭通','杭州','湖州','嘉兴','金华','丽水','宁波','绍兴','台州','温州','舟山','衢州','重庆','香港','澳门','台湾','合肥','义乌');

}


?>