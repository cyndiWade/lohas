<?php

/**
 * 	全局参数类
 */
class GlobalParameterAction extends Action {
	
	protected $add_db = array();		//追加的DB对象
	
	protected $db = array();				//数据库对象
	
	/* 保存用户信息，供全局调用 */
	protected $global_system;			//全局系统变量
	
	protected $oUser;						//全局身份标示
	
	protected $order_status;				//订单状态

	protected $dispose_status;			//处理状态
	

	
	/**
	 * 构造方法
	 */
	public function __construct() {
		parent:: __construct();			//重写父类构造方法
		$this->GlobalParameterInit();
	}

	//初始化方法
	private function GlobalParameterInit () {
		$this->order_status = C('ORDER_STATUS');
		$this->dispose_status = C('DISPOSE_STATUS');
	}

	
}


?>