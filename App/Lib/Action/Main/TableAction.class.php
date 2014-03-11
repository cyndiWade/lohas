<?php
/**
 * 
 */
class TableAction extends MainBaseAction {
    

	public function component_table_default ()    {
		
		$this->display();
	}

	
	public function component_table_sortable () {
		$this->display();
	}
	
    
}