<?php

/**
 * 用户访问权限
 */

class RBAC { 
	
	/* 数据表配置 */
	private static $table_prefix;					//数据库表前缀
	private static $node_table;						//节点表（系统所有资源）
	private static $group_table;						//组表
	private static $group_node_table;			//组与节点关系表
	private static $group_user_table;				//组与用户关系表
	
	private static $action;							//URL当前动作
	private static $not_auth_group;			//无需认证分组
	private static $not_auth_module;			//无需认真模块
	private static $not_auth_action;			//无需认证操作
	/**
	 * 初始化
	 */
	static public function init($parameter) {
		
		/* 数据表 */
		self::$table_prefix = $parameter->table_prefix;		//表前缀
		self::$node_table = $parameter->node_table;		//节点表
		self::$group_table = $parameter->group_table;		//组表
		self::$group_node_table = $parameter->group_node_table;			//组与节点关系表
		self::$group_user_table = $parameter->group_user_table;			//组与用户关系表
		
		/* 当前动作 */
		self::$action = array(
				1 => $parameter->group,
				2 => $parameter->module,
				3 => $parameter->action
		);		
		
		/* 无需认证过滤 */
		self::$not_auth_group =  explode(',', $parameter->not_auth_group);				//无需认证分组
		self::$not_auth_module = explode(',', $parameter->not_auth_module);			//无需认证模块
		self::$not_auth_action = explode(',', $parameter->not_auth_action);				//无需认证操作
		
		$parameter = null;	//清除对象引用，释放资源
	}
	
	/**
	 * 验证权限
	 * $UID INT (用户表的主键ID)
	 */
	 static public function check ($uid) {
		header('Content-Type:text/html;charset=utf-8');
		$result = array('status' => false,'message' => '');
			
		if (in_array(self::$action[1],self::$not_auth_group) || in_array(self::$action[2],self::$not_auth_module) || in_array(self::$action[3], self::$not_auth_action)) {
			$result['status'] = true;
			$result['message'] = '放行，当前模块无需认证';
			return $result;
		}
		
		/* 获取用户存在的权限 */
		$DB = M();
		$rbac_list = $DB->field('gn.group_id,n.name,n.title,n.level')
		->table(self::$table_prefix.self::$group_user_table.' AS gu')
		->join(self::$table_prefix.self::$group_node_table.' AS gn ON gu.group_id = gn.group_id')
		->join(self::$table_prefix.self::$node_table.' AS n ON gn.node_id = n.id')
		->where(array('gu.user_id'=>$uid,'n.status'=>0))
		->select();
		
		/* 未分配组处理 */
		if (empty($rbac_list)) {
			$result['status'] = false;
			$result['message'] = '未分配组,无法访问：'.implode(',',self::$action);
			return $result;
		}
		
		/* 按照组来排序用户已有的权限 */
		$rbac_group = array();		
		foreach ($rbac_list AS $key=>$val) {
			$rbac_group[$val['group_id']][] = $val;
		}	
		

		/* 权限验证 */
		/* 获取已有的权限 */
		$have_jurisdiction = array();		
		foreach ($rbac_group AS $groupKey=>$groupVal) {
			foreach ($groupVal AS $key=>$val) {
				//验证当前组中，已有的权限
				if ($val['name'] == self::$action[$val['level']]) {
					$have_jurisdiction[$groupKey][$val['level']] = $val['name']; 	//保存已有的权限
				}
			}
		}


		/* 拿已有的权限与URL的动作进行对比 */
		foreach ($have_jurisdiction AS $key=>$val) {
			$tmp = array_diff(self::$action,$val);	//计算URL动作与已有权限的差集
		
			/* 如果没有差集，则表示有权限访问 */
			if (empty($tmp)) {
				$result['status'] = true;
				$result['message'] = '放行，验证通过';
				break;
			} else {
				$result['status'] = false;
				$result['message'] = '你没有权限访问：'.implode(',',$tmp);
			}
		}
		return $result;
	}
	
}



?>