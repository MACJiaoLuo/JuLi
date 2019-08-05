<?php

		//聚力网络科技 版权所有
		//官网：http://www.juliwangluo.cn
		//何以潇QQ：1744744222

	
	//看的懂自己去弄   看不懂自己改C流控脚本
	
	
	//使用之前请先配置数据库
	
	
	//主程序
	
	function getIp(){
    $IPaddress='';
    if (isset($_SERVER)){
        if (isset($_SERVER["HTTP_X_FORWARDED_FOR"])){
            $IPaddress = $_SERVER["HTTP_X_FORWARDED_FOR"];
        } else if (isset($_SERVER["HTTP_CLIENT_IP"])) {
            $IPaddress = $_SERVER["HTTP_CLIENT_IP"];
        } else {
            $IPaddress = $_SERVER["REMOTE_ADDR"];
        }
    } else {
        if (getenv("HTTP_X_FORWARDED_FOR")){
            $IPaddress = getenv("HTTP_X_FORWARDED_FOR");
        } else if (getenv("HTTP_CLIENT_IP")) {
            $IPaddress = getenv("HTTP_CLIENT_IP");
        } else {
            $IPaddress = getenv("REMOTE_ADDR");
        }
    }
    return $IPaddress;
}
	//获取来访IP  如果来自代理IP，可能获取真实IP失败！
    $IP = getIp();
	
	
	
	
	
	$DB_Host = "localhost:3306";
	$DB_User = "账户";
	$DB_Pass = "密码";
	$DB_Name = "数据库";
	
	
	
	
	
	if($_GET["act"]=="web"){ 
	$conn = new mysqli($DB_Host, $DB_User, $DB_Pass, $DB_Name);
	if ($conn->connect_error) {
		die("数据库连接失败: " . $conn->connect_error);
	} 
 
	$sql = "select * from cwinet_code where url='$IP'";
	$result = $conn->query($sql);
 
 
 
 //if 判断
	if ($result->num_rows > 0) {
		//正版授权用户才可下载文件，盗版用户无法下载
		$file_name = $_GET["file_name"];
		
		//你的源存放服务器位置，将通过download.php文件下载
		$file_dir = "/var/Resources/JuLiNB6666_web/";
	
		if (! file_exists ( $file_dir . $file_name )) {    
			header('HTTP/1.1 403 Forbidden');
		}else{
			$file = fopen ( $file_dir . $file_name, "rb" );  
			Header ( "Content-type: application/octet-stream" );
			Header ( "Accept-Ranges: bytes" );
			Header ( "Accept-Length: " . filesize ( $file_dir . $file_name ) );
			Header ( "Content-Disposition: attachment; filename=" . $file_name ); 
			echo fread ( $file, filesize ( $file_dir . $file_name ) );
			fclose ( $file );
			exit ();
		}
		
		
	}else{
		
		//盗版用户  403
		
		
		header('HTTP/1.1 403 Forbidden');
		
	}
	$conn->close();
	
	
	
	//检查授权
	}elseif($_GET["act"]=="check"){
		
		$conn = new mysqli($DB_Host, $DB_User, $DB_Pass, $DB_Name);
		if ($conn->connect_error) {
			die("数据库连接失败: " . $conn->connect_error);
		} 
 
		$sql = "select * from cwinet_code where url='$IP'";
		$result = $conn->query($sql);
 
		if ($result->num_rows > 0) {
			//正版
			echo "Genuine";
		}else{
			//盗版
			echo "Pirate";
		}
		$conn->close();
	
	
	
	//上传盗版用户IP
	}elseif($_GET["act"]=="upload"){
		
		//读取数据库配置
	
			include "MySQL.php";

			$Server_IP = $_GET["ip"];
			$status = "1";
			$intime = date("Y-m-d H:i:s");
			
			
			if (empty($Server_IP)){	
			echo '
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL err was not found on this server.</p>
</body></html>
';
			exit;
			}else{
			//echo '';
			}
			
			$conn = new mysqli($DB_Host, $DB_User, $DB_Pass, $DB_Name);
			// 检测连接
			if ($conn->connect_error) {
 			   die("数据库连接失败: " . $conn->connect_error);
			} 
			//写入数据库
			$sql = "INSERT INTO Blacklist_users (IP, Status, Time) VALUES ('$Server_IP', '$status', '$intime')";
 
			if ($conn->query($sql) === TRUE) {
				
				//写入数据库成功
   			echo '
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL yes was not found on this server.</p>
</body></html>';
			exit;
			}else{
				
				//写入失败，请检查数据库
			echo '
<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>404 Not Found</title>
</head><body>
<h1>Not Found</h1>
<p>The requested URL error was not found on this server.</p>
</body></html>';
			exit;
			}
 
$conn->close();
			
			
		
	}else{
		
		//直接访问此文件显示403
		header('HTTP/1.1 403 Forbidden');
	}

?>