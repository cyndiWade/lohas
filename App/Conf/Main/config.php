<?php
if (!defined('THINK_PATH'))exit();

return array(
		
	//	'DEFAULT_GROUP'         => 'Admin',  // 默认分组
	//	'DEFAULT_MODULE'        => 'Index', // 默认模块名称
	//	'DEFAULT_ACTION'        => 'index', // 默认操作名称
		

		/* 后台不需要验证的模块 */
		'USER_AUTH_ON' => false,						//是否开启用户权限验证
		'RBAC_NODE_TABLE' => 'node',				//节点表（系统所有资源）
		'RBAC_GROUP_TABLE' => 'group',			//组表
		'RBAC_GROUP_NODE_TABLE'	=>'group_node',	//组与节点关系表
		'RBAC_GROUP_USER_TABLE'	=>'group_user',	//组与用户关系表
		
		'ADMIN_AUTH_KEY' => 'admin',					//管理员账号标识，不用认证的账号
		//'NOT_AUTH_GROUP'=> '',						//无需认证分组，多个用,号分割
		'NOT_AUTH_MODULE' => 'Login', 				// 默认无需认证模块，多个用,号分割
		'NOT_AUTH_ACTION' => '', 						// 默认无需认证方法，多个用,号分割
		
		
);
?>