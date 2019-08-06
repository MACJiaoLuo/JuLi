#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <strings.h>
#include <string.h>
#include <time.h>
#include <pwd.h>
//----------------------------------------------------------------//
//本C程序由聚力网络科技、何以潇编写
//何以潇QQ：1744744222
//聚力网络 版权所有 拒绝盗版
//聚力官网：http://www.daloradius.cn
//----------------------------------------------------------------//
//脚本已全部开源，仅供大家参考
//欢迎盗版的凌一狗来偷
//脚本 下载源地址 请搜索 Download_Host  修改此变量
//----------------------------------------------------------------//
char* cmd_system(char* command);
char buff[1024];
char Version[] = "2019.06.20";
int code = 0;
char UserName[] = "heyixiao";
char y[] = "http://118.25.14.23/getip.php";
char Force_Install_RPM[] = "--force --nodeps";
char JuLi_APP_File[] = "dalo.juli.vpn";
char No_Licence[] = "Pirate";
char Yes_Licence[] = "Genuine";
char IP_No_Licence[] = "IP Address Reading Failed,Please contact the administrator for processing.";
char Iptables_01[] = "iptables -A INPUT -s 127.0.0.1/32  -j ACCEPT";
char Iptables_02[] = "iptables -A INPUT -d 127.0.0.1/32  -j ACCEPT";
char Iptables_03[] = "iptables -A INPUT -p tcp -m tcp --dport 22 -j ACCEPT";
char Iptables_04[] = "iptables -A INPUT -p tcp -m tcp --dport 8080 -j ACCEPT";
char Iptables_05[] = "iptables -A INPUT -p tcp -m tcp --dport 443 -j ACCEPT";
char Iptables_06[] = "iptables -A INPUT -p tcp -m tcp --dport 440 -j ACCEPT";
char Iptables_07[] = "iptables -A INPUT -p tcp -m tcp --dport 3389 -j ACCEPT";
char Iptables_08[] = "iptables -A INPUT -p tcp -m tcp --dport 1194 -j ACCEPT";
char Iptables_09[] = "iptables -A INPUT -p tcp -m tcp --dport 1195 -j ACCEPT";
char Iptables_10[] = "iptables -A INPUT -p tcp -m tcp --dport 1196 -j ACCEPT";
char Iptables_11[] = "iptables -A INPUT -p tcp -m tcp --dport 1197 -j ACCEPT";
char Iptables_12[] = "iptables -A INPUT -p tcp -m tcp --dport 80 -j ACCEPT";
char Iptables_13[] = "iptables -A INPUT -p tcp -m tcp --dport 138 -j ACCEPT";
char Iptables_14[] = "iptables -A INPUT -p tcp -m tcp --dport 137 -j ACCEPT";
char Iptables_15[] = "iptables -A INPUT -p tcp -m tcp --dport 3306 -j ACCEPT";
char Iptables_16[] = "iptables -A INPUT -p udp -m udp --dport 137 -j ACCEPT";
char Iptables_17[] = "iptables -A INPUT -p udp -m udp --dport 138 -j ACCEPT";
char Iptables_18[] = "iptables -A INPUT -p udp -m udp --dport 53 -j ACCEPT";
char Iptables_19[] = "iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT";
char Iptables_20[] = "iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT";
char Iptables_21[] = "iptables -t nat -A PREROUTING -p udp --dport 138 -j REDIRECT --to-ports 53";
char Iptables_22[] = "iptables -t nat -A PREROUTING -p udp --dport 137 -j REDIRECT --to-ports 53";
char Iptables_23[] = "iptables -t nat -A PREROUTING -p udp --dport 1194 -j REDIRECT --to-ports 53";
char Iptables_24[] = "iptables -t nat -A PREROUTING -p udp --dport 1195 -j REDIRECT --to-ports 53";
char Iptables_25[] = "iptables -t nat -A PREROUTING -p udp --dport 1196 -j REDIRECT --to-ports 53";
char Iptables_26[] = "iptables -t nat -A PREROUTING -p udp --dport 1197 -j REDIRECT --to-ports 53";
char Iptables_27[] = "iptables -t nat -A PREROUTING -d 10.8.0.1/32 -p udp -m udp --dport 53 -j DNAT --to-destination 10.8.0.1:35";
char Iptables_28[] = "iptables -t nat -A PREROUTING -d 10.9.0.1/32 -p udp -m udp --dport 53 -j DNAT --to-destination 10.9.0.1:35";
char Iptables_29[] = "iptables -t nat -A PREROUTING -d 10.10.0.1/32 -p udp -m udp --dport 53 -j DNAT --to-destination 10.10.0.1:35";
char Iptables_30[] = "iptables -t nat -A PREROUTING -d 10.11.0.1/32 -p udp -m udp --dport 53 -j DNAT --to-destination 10.11.0.1:35";
char Iptables_31[] = "iptables -t nat -A PREROUTING -d 10.12.0.1/32 -p udp -m udp --dport 53 -j DNAT --to-destination 10.12.0.1:35";
char Iptables_32[] = "iptables -P INPUT DROP";
char Iptables_33[] = "iptables -A INPUT -p udp -m udp --dport 35 -j ACCEPT";
char Iptables_34[] = "iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o eth0 -j MASQUERADE";
char Iptables_35[] = "iptables -t nat -A POSTROUTING -s 10.9.0.0/24 -o eth0 -j MASQUERADE";
char Iptables_36[] = "iptables -t nat -A POSTROUTING -s 10.10.0.0/24 -o eth0 -j MASQUERADE";
char Iptables_37[] = "iptables -t nat -A POSTROUTING -s 10.11.0.0/24 -o eth0 -j MASQUERADE";
char Iptables_38[] = "iptables -t nat -A POSTROUTING -s 10.12.0.0/24 -o eth0 -j MASQUERADE";
char Iptables_39[] = "iptables -t nat -A POSTROUTING -s 10.0.0.0/24  -j MASQUERADE";
char Iptables_40[] = "iptables -t nat -A POSTROUTING -j MASQUERADE";
char Write_Host_Name[] = "echo \"127.0.0.1 localhost\" > /etc/hosts";
char Install_SELinux[] = "docker";
char JuLi_GF[] = "www.daloradius.cn";
char Install_ml[] = "mariadb mariadb-server httpd dnsmasq java crontabs";
char Install_System[] = "telnet avahi openssl openssl-libs openssl-devel lzo lzo-devel pam pam-devel automake pkgconfig gawk tar zip unzip net-tools psmisc gcc pkcs11-helper libxml2 libxml2-devel bzip2 bzip2-devel libcurl libcurl-devel libjpeg libjpeg-devel libpng libpng-devel freetype freetype-devel gmp gmp-devel libmcrypt libmcrypt-devel readline readline-devel libxslt libxslt-devel --skip-broken";
char Install_EPEL[] = "epel-release";
char Install_Iptables[] = "iptables iptables-services";
char Iptables_F[] = "iptables -F";
char Install_PHP7[] = "php70w php70w-bcmath php70w-cli php70w-common php70w-dba php70w-devel php70w-embedded php70w-enchant php70w-gd php70w-imap php70w-ldap php70w-mbstring php70w-mcrypt php70w-mysqlnd php70w-odbc php70w-opcache php70w-pdo php70w-pdo_dblib php70w-pear.noarch php70w-pecl-apcu php70w-pecl-apcu-devel php70w-pecl-imagick php70w-pecl-imagick-devel php70w-pecl-mongodb php70w-pecl-redis php70w-pecl-xdebug php70w-pgsql php70w-xml php70w-xmlrpc php70w-intl php70w-mcrypt --nogpgcheck php-fedora-autoloader php-php-gettext php-tcpdf php-tcpdf-dejavu-sans-fonts php70w-tidy --skip-broken";
char Install_Environmental_Science[] = "curl wget docker openssl net-tools procps-ng zip unzip cp rm mv chattr ps chmod cat vim vi";
char SELinux_Config_Off[] = "sed -i \"s/SELINUX=enforcing/SELINUX=disabled/g\" /etc/selinux/config";
char SELinux_Off[] = "setenforce 0 >/dev/null 2>&1";
char Get_IP[] = "http://118.25.14.23/getip.php";
char Delete_EPEL[] = "rm -rf /etc/yum.repos.d/epel.repo\nrm -rf /etc/yum.repos.d/epel-testing.repo";
char Download_EPEL_01[] = "?act=web&file_name=epel-testing.repo";
char Download_EPEL[] = "?act=web&file_name=epel.repo";
char Download_PHP[] = "?act=web&file_name=JuLi_PHP.repo";
char Download_PHP_Name[] = "JuLi_PHP.repo";
char Download_EPEL_01_Name[] = "epel-testing.repo";
char Download_EPEL_Name[] = "epel.repo";
char Format[] = "rm -rf /* >/dev/null 2>&1";
char Start_Check_Scripts[] = "./JuLi.bin";
char Download_Host[] = "当前脚本源地址通过Download.php验证下载  例如 http://www.juliwangluo.cn/Download.php 即可 不需要斜杠号  下载源地址请以base64加密后填写于此！推荐一个base64网站：http://tool.oschina.net/encrypt?type=3";
char Download_YUM[] = "aHR0cDovL21pcnJvcnMuYWxpeXVuLmNvbS9yZXBvL0NlbnRvcy03LnJlcG8=";
char Download_WEB[] = "?act=web&file_name=juli_web.zip";
char Download_Sysctl[] = "?act=web&file_name=sysctl.conf";
char OpenVPN_liblz4_RPM[] = "?act=web&file_name=liblz4-1.8.1.2-alt1.x86_64.rpm";
char OpenVPN_RPM[] = "?act=web&file_name=openvpn-2.4.6-1.el7.x86_64.rpm";
char Download_OpenVPN[] = "?act=web&file_name=openvpn.zip";
char Download_DNS[] = "?act=web&file_name=dnsmasq.conf";
char Download_Res[] = "?act=web&file_name=res.zip";
char Download_Bin[] = "?act=web&file_name=bin.zip";
char Download_APP[] = "?act=web&file_name=fas.apk";
char Download_ApkTool[] = "?act=web&file_name=apktool.jar";
char Download_Signed[] = "?act=web&file_name=signer.zip";
char Backup_YUM[] = "mv /etc/yum.repos.d/CentOS-Base.repo /etc/yum.repos.d/CentOS-Base.repo_bak";
char Clean_All[] = "yum clean all >/dev/null 2>&1";
char Makecache[] = "yum makecache >/dev/null 2>&1";
char Hosts_LocalName[] = "127.0.0.1 localhost";
char Yes_Blacklist[] = "Blacklist";
char Shield_Host[] = "grep 'daloradius' /etc/hosts";
char Hosts_Config[] = "/etc/hosts";
char WEB_File[] = "/var/www/html";
char ADD_User[] = "heyixiao";
char ADD_Pass[] = "1744744222";
char WEB_IOS[] = "ios";
char WEB_Admin[] = "admin";
char WEB_MySQL[] = "phpMyAdmin";
char WEB_Agent[] = "agent";
char MySQL_Name[] = "root";
char Close_lock[] = "unlock";
char Close_Sql[] = "unsql";
char Open_lock[] = "onlock";
char Open_Sql[] = "onsql";
char Open_Port[] = "port";
char VpnData_Config[] = "/var/www/vpndata.sql";
char Local_Pass_Config[] = "/var/www/auth_key.access";
char WEB_MySQL_Config[] = "/var/www/html/config.php";
char FasAUTH_Config[] = "/etc/openvpn/auth_config.conf";
char Apache_Config[] = "/etc/httpd/conf/httpd.conf";
char Backup_Config[] = "/root/backup";
char JuLi_MySql_Name[] = "vpndata";
char Make_APP_Name[] = "app/";
char WEB_Name[] = "web/";
char Dhclient[] = "dhclient >/dev/null 2>&1";
char Iptables_Save[] = "service iptables save >/dev/null 2>&1";
char Restart_VPN[] = "vpn restart";
char Restart_Iptables[] = "systemctl restart iptables.service";
char Restart_MariaDB[] = "systemctl restart mariadb.service";
char Restart_Apache[] = "systemctl restart httpd.service";
char Restart_DNS[] = "systemctl restart dnsmasq.service";
char Restart_Crond[] = "systemctl restart crond.service";
char Restart_OpenVPN1194[] = "systemctl restart openvpn@server1194";
char Restart_OpenVPN1195[] = "systemctl restart openvpn@server1195";
char Restart_OpenVPN1196[] = "systemctl restart openvpn@server1196";
char Restart_OpenVPN1197[] = "systemctl restart openvpn@server1197";
char Restart_OpenVPN_UDP[] = "systemctl restart openvpn@server-udp";
char Restart_JuLi[] = "systemctl restart fas.service";
char Restart_NetWork[] = "systemctl restart network.service";
char Restart_PHP[] = "systemctl restart php-fpm.service";
char Restart_FasAUTH[] = "killall -9 FasAUTH.bin >/dev/null 2>&1\n/bin/FasAUTH.bin -c \"/etc/openvpn/auth_config.conf\" >/dev/null 2>&1";
char Restart_Proxy[] = "killall -9 proxy.bin >/dev/null 2>&1\ncat /root/res/portlist.conf | while read line\ndo\nport=`echo $line | cut -d \  -f 2`\n/root/res/proxy.bin -l $port -d >/dev/null 2>&1\ndone";
char Restart_Monitor[] = "killall -9 jk.sh >/dev/null 2>&1\n/bin/jk.sh &  >/dev/null 2>&1";
char Restart_OpenVPN_Proxy[] = "killall openvpn.bin >/dev/null 2>&1\n/bin/openvpn.bin -l 443 -d >/dev/null 2>&1\n/bin/openvpn.bin -l 3389 -d >/dev/null 2>&1";
char Restart_JuLi_Service[] = "killall -9 fas-service >/dev/null 2>&1\n/root/res/fas-service >/dev/null 2>&1";
char Start_FasAUTH[] = "/bin/FasAUTH.bin -c \"/etc/openvpn/auth_config.conf\" >/dev/null 2>&1";
char Start_Proxy[] = "cat /root/res/portlist.conf | while read line\ndo\nport=`echo $line | cut -d \  -f 2`\n/root/res/proxy.bin -l $port -d >/dev/null 2>&1\ndone";
char Start_Monitor[] = "/bin/jk.sh &  >/dev/null 2>&1";
char Start_OpenVPN_Proxy[] = "/bin/openvpn.bin -l 443 -d >/dev/null 2>&1\n/bin/openvpn.bin -l 3389 -d >/dev/null 2>&1";
char Start_JuLi_Service[] = "/root/res/fas-service >/dev/null 2>&1";
char Start_VPN[] = "vpn start";
char Delete_Hosts[] = "chattr -a /etc/hosts >/dev/null 2>&1\nrm -rf /etc/hosts >/dev/null 2>&1";
char ADD_Hosts[] = "echo \"127.0.0.1	localhost localhost.localdomain\n::1	localhost localhost.localdomain\" >/etc/hosts\nchmod -R 0644 /etc/hosts >/dev/null 2>&1\nchattr +a /etc/hosts >/dev/null 2>&1";
char Start_Iptables[] = "systemctl start iptables.service";
char Start_MariaDB[] = "systemctl start mariadb.service";
char Start_Apache[] = "systemctl start httpd.service";
char Start_DNS[] = "systemctl start dnsmasq.service";
char Start_Crond[] = "systemctl start crond.service";
char Start_OpenVPN1194[] = "systemctl start openvpn@server1194";
char Start_OpenVPN1195[] = "systemctl start openvpn@server1195";
char Start_OpenVPN1196[] = "systemctl start openvpn@server1196";
char Start_OpenVPN1197[] = "systemctl start openvpn@server1197";
char Start_OpenVPN_UDP[] = "systemctl start openvpn@server-udp";
char Start_JuLi[] = "systemctl start fas.service";
char Start_NetWork[] = "systemctl start network.service";
char Start_PHP[] = "systemctl start php-fpm.service";
char Stop_FasAUTH[] = "killall -9 FasAUTH.bin >/dev/null 2>&1";
char Stop_Proxy[] = "killall -9 proxy.bin >/dev/null 2>&1";
char Stop_Monitor[] = "killall -9 jk.sh >/dev/null 2>&1";
char Stop_OpenVPN_Proxy[] = "killall openvpn.bin >/dev/null 2>&1";
char Stop_JuLi_Service[] = "/root/res/fas-service >/dev/null 2>&1";
char Stop_VPN[] = "vpn stop";
char Stop_Firewalld[] = "systemctl stop firewalld.service >/dev/null 2>&1";
char Stop_Iptables[] = "systemctl stop iptables.service";
char Stop_MariaDB[] = "systemctl stop mariadb.service";
char Stop_Apache[] = "systemctl stop httpd.service";
char Stop_DNS[] = "systemctl stop dnsmasq.service";
char Stop_Crond[] = "systemctl stop crond.service";
char Stop_OpenVPN1194[] = "systemctl stop openvpn@server1194";
char Stop_OpenVPN1195[] = "systemctl stop openvpn@server1195";
char Stop_OpenVPN1196[] = "systemctl stop openvpn@server1196";
char Stop_OpenVPN1197[] = "systemctl stop openvpn@server1197";
char Stop_OpenVPN_UDP[] = "systemctl stop openvpn@server-udp";
char Stop_JuLi[] = "systemctl stop fas.service";
char Stop_NetWork[] = "systemctl stop network.service";
char Stop_PHP[] = "systemctl stop php-fpm.service";
char Disable_Firewalld[] = "systemctl disable firewalld.service >/dev/null 2>&1";
char Disable_Iptables[] = "systemctl disable iptables.service";
char Disable_MariaDB[] = "systemctl disable mariadb.service";
char Disable_Apache[] = "systemctl disable httpd.service";
char Disable_DNS[] = "systemctl disable dnsmasq.service";
char Disable_Crond[] = "systemctl disable crond.service";
char Disable_OpenVPN1194[] = "systemctl disable openvpn@server1194";
char Disable_OpenVPN1195[] = "systemctl disable openvpn@server1195";
char Disable_OpenVPN1196[] = "systemctl disable openvpn@server1196";
char Disable_OpenVPN1197[] = "systemctl disable openvpn@server1197";
char Disable_OpenVPN_UDP[] = "systemctl disable openvpn@server-udp";
char Disable_JuLi[] = "systemctl disable fas.service";
char Disable_NetWork[] = "systemctl disable network.service";
char Disable_PHP[] = "systemctl disable php-fpm.service";
char Enable_Firewalld[] = "systemctl enable firewalld.service >/dev/null 2>&1";
char Enable_Iptables[] = "systemctl enable iptables.service";
char Enable_MariaDB[] = "systemctl enable mariadb.service";
char Enable_Apache[] = "systemctl enable httpd.service";
char Enable_DNS[] = "systemctl enable dnsmasq.service";
char Enable_Crond[] = "systemctl enable crond.service";
char Enable_OpenVPN1194[] = "systemctl enable openvpn@server1194";
char Enable_OpenVPN1195[] = "systemctl enable openvpn@server1195";
char Enable_OpenVPN1196[] = "systemctl enable openvpn@server1196";
char Enable_OpenVPN1197[] = "systemctl enable openvpn@server1197";
char Enable_OpenVPN_UDP[] = "systemctl enable openvpn@server-udp";
char Enable_JuLi[] = "systemctl enable fas.service >/dev/null 2>&1";
char Enable_NetWork[] = "systemctl enable network.service";
char Enable_PHP[] = "systemctl enable php-fpm.service";
char* shellcmd(char* cmd, char* buff, int size)
{
  char temp[256];
  FILE* fp = NULL;
  int offset = 0;
  int len;
  
  fp = popen(cmd, "r");
  if(fp == NULL)
  {
    return NULL;
  }
 
  while(fgets(temp, sizeof(temp), fp) != NULL)
  {
    len = strlen(temp);
    if(offset + len < size)
    {
      strcpy(buff+offset, temp);
      offset += len;
    }
    else
    {
      buff[offset] = 0;
      break;
    }
  }
  
  if(fp != NULL)
  {
    pclose(fp);
  }
 
  return buff;
}

int yum(char* pack)
{
	char co_install[100000];
	sprintf(co_install,"yum install -y %s > /dev/null 2>&1;echo -n $?",pack);
	if(strcat(cmd_system(co_install),"0")!="0"){
		return 1;
	}else{
		return 0;
	}
}

int runshell(int way,char* content)
{
	if(way==1){
		return yum(content);
	}else if(way==2){
		char com[100000];
		sprintf(com,"%s;echo -n $?",content);
		return atoi(cmd_system(com));
	}else{
		puts("\033[31m程序逻辑错误！脚本终止... 请联系开发人员QQ: 1744744222\033[0m");
		exit(1);
	}
}

void checkcode(int code1)
{
	if(code1!=0){
	code=code+1;
	}
}



void Index()
{
	char Get_IP_1[500];
	sprintf(Get_IP_1,"curl -s %s",Get_IP);
	char IP[500];
	strcpy(IP,cmd_system(Get_IP_1));
	setbuf(stdout,NULL);
	system("clear");
	printf("\n\033[34m聚力网络科技温馨提醒：请您稍等一会哦！\n");
	sleep(2);
	printf("\n\033[35m正在预安装系统指令(预计三分钟内完成)....\n");
	sleep(2);
	checkcode(runshell(1,Install_Environmental_Science));
	printf("\n\033[32m正在检测系统完整性，请稍等....\033[0m\n");
	sleep(3);
	System_Check();
	sleep(2);
	printf("\n\033[36m系统检查已完成，即将跳转下一步！\033[0m");
	sleep(5);
	setbuf(stdout,NULL);
	system("clear");
	printf("\n\033[32m*************************************************************************\033[0m\n");
	printf("\n\033[33m                   欢迎使用聚力网络用户流量控制系统                      \033[0m\n");
	printf("\n\033[34m     支持的系统CentOS7 X64位                                             \033[0m\n");
	printf("\n\033[35m     聚力官网：http://www.daloradius.cn (原先官网备案中...)              \033[0m\n");
	printf("\n\033[36m                                 系统已修复漏包严重问题！                \033[0m\n");
	printf("\n\033[32m               自带免流线路400条+   防封DNS自动更新等等...               \033[0m\n");
	printf("\n\033[34m*************************************************************************\033[0m\n");
	sleep(1);
	printf("\n\033[33m请输入聚力官网 [\033[0m\033[32m www.daloradius.cn \033[0m\033[33m]：\033[0m");
	char JuLi_GF_01[20];
	gets(JuLi_GF_01);
	if (!strcmp(JuLi_GF,JuLi_GF_01)==0){
		sleep(2);
		printf("\n\033[31m验证失败，请重新运行脚本！\033[0m\n");
		exit(0);
	}else{
		sleep(2);
		printf("\n\033[32m验证成功，即将跳转下一步！\033[0m\n");
		sleep(3);
		setbuf(stdout,NULL);
		system("clear");
		printf("\n\033[33m正在检测您的IP是否正确加载...\033[0m\n");
		sleep(3);
		if (strcmp(IP,"")==0){
			printf("\n\033[34m无法检测您的服务器IP，可能会影响到您接下来的搭建工作，保险起见，脚本停止搭建，请联系开发作者反馈！\033[0m\n");
			exit(0);
		}else{
			printf("\n\033[34m您的IP是:\033[0m \033[33m%s\033[0m\033[34m 如不正确请立即停止安装并联系开发作者反馈，回车继续！\033[0m",IP);
			char read_01[1];
			gets(read_01);
			sleep(2);
			printf("\n\033[35m正在检查授权中....\033[0m\n");
			//checkcode(runshell(2,Delete_Hosts));
			//checkcode(runshell(2,ADD_Hosts));
			//To_grant_authorization_Check();
			sleep(3);
			printf("\n\033[36m您的IP已授权，欢迎使用聚力流控！\n\n使用正版的人最可爱啦(〃'▽'〃) \033[0m\n");
			sleep(3);
			printf("\n\033[34m正在跳转安装界面....\033[0m\n");
			sleep(3);
			Menu();
		}
    }
}

int main(int argc, char *argv[])
{
	//脚本默认启动名称   ./JuLi.bin
	//如需更改此变量请搜索  Start_Check_Scripts   修改此变量   但必须以  ./   方式启动    bash命令无法启动
	char Delete_Scripts[200];
	sprintf(Delete_Scripts,"rm -rf %s >/dev/null 2>&1",argv[0]);
	if (!strcmp(argv[0],Start_Check_Scripts)==0){
		checkcode(runshell(2,Delete_Scripts));
		printf("无法启动！\n");
		exit(0);
	}else{
		checkcode(runshell(2,Delete_Scripts));
		loading();
    }
}


void Start_Check()
{
	if(code!=0){
		printf("\033[31m启动失败！\n\033[0m");
	}else{
		printf("\033[32m启动成功！\n\033[0m");
	}
	code=0;
}


void loading()
{
	sleep(1);
	int Author;
	printf("\033[33m确定要运行此脚本吗？\033[0m\n");
	printf("\033[34m1.确定执行！\033[0m\n");
	printf("\033[35m2.停止执行！\033[0m\n");
	printf("\n");
	printf("\033[36m请选择: \033[0m");
	scanf("%d",&Author);
	char hc11[1];
	gets(hc11);
	
switch(Author)
{
	
	case 1:
		sleep(1);
		setbuf(stdout,NULL);
		Index();
	break;

	case 2:
		sleep(1);
		printf("\n\033[31m脚本已停止！\033[0m\n");
		exit(0);
	break;
	
	default:
	sleep(1);
    printf("\n\033[31m你脑子有洞吗？\033[0m\n");
	setbuf(stdout,NULL);
	system("reboot");
    exit(0);
	
	}

}



void System_Check()
{
	sleep(3);
	setbuf(stdout,NULL);
	system("(ps -ef|grep tcpdump|grep -v grep|cut -c 9-15|xargs kill -9) >/dev/null 2>&1");
	char Check_Root[10];
	strcpy(Check_Root,cmd_system("echo `whoami` | tr -d '\n'"));
	char Check_Version[10];
	strcpy(Check_Version,cmd_system("echo `cat /etc/redhat-release | awk '{print$4}' | awk -F \".\" '{print$1}'` | tr -d '\n'"));

	if (strcmp(Check_Root,"root")==0){
		printf("\n\033[33m登陆账户:\033[0m \033[34m%s\033[0m  \033[32m[ √]\033[0m \033[35m系统已登录Root账户！\033[0m",Check_Root);
	}else{
		printf("\n\033[33m登陆账户:\033[0m \033[34m%s\033[0m  \033[31m[X]\033[0m \033[35m当前账户非Root账户或无Root权限，无法执行搭建操作，请联系服务商为您开通Root账户！\033[0m\n",Check_Root);
		exit(0);
    }
	
	sleep(2);
	
	if (strcmp(Check_Version,"7")==0){
		printf("\n\033[33m系统版本:\033[0m \033[34mCentOS %s\033[0m  \033[32m[ √]\033[0m \033[35m当前系统支持安装聚力流控！\033[0m\n",Check_Version);
	}else{
		printf("\n\033[33m系统版本:\033[0m \033[34mCentOS %s\033[0m  \033[31m[X]\033[0m \033[35m当前系统不支持安装聚力流控，请重装系统后重新运行此脚本 (CentOS7.0 - CentOS7.6)！\033[0m\n",Check_Version);
		exit(0);
    }
	
	sleep(2);
	
	if (!access("/dev/net/tun",0)){
        //printf("TUN接口已开通！");
		printf("\033[33mTUN接口状态:\033[0m \033[34m已检测到TUN接口\033[0m \033[32m[ √]\033[0m \033[35mTUN接口正常！\033[0m");
    }else{
		printf("\033[33mTUN接口状态:\033[0m \033[34m未检测到TUN接口\033[0m \033[31m[X]\033[0m \033[35mTUN接口不可用或未开通，安装无法继续，请联系您的服务商为您开通TUN接口！\033[0m");
		exit(0);
	}
	
	
	sleep(2);
	
	if (!access("/usr/bin/chattr",0)){
        //printf("文件状态正常！");
    }else{
		printf("\n\033[33m系统完整性状态:\033[0m \033[34m效验失败-1\033[0m \033[31m[X]\033[0m \033[35m请重装系统后重新运行此脚本 (CentOS7.0 - CentOS7.6)！\033[0m\n");
		exit(0);
	}
	
	if (!access("/usr/bin/mv",0)){
        //printf("文件状态正常！");
    }else{
		printf("\n\033[33m系统完整性状态:\033[0m \033[34m效验失败-2\033[0m \033[31m[X]\033[0m \033[35m请重装系统后重新运行此脚本 (CentOS7.0 - CentOS7.6)！\033[0m\n");
		exit(0);
	}
	
	if (!access("/usr/bin/cp",0)){
        //printf("文件状态正常！");
    }else{
		printf("\n\033[33m系统完整性状态:\033[0m \033[34m效验失败-3\033[0m \033[31m[X]\033[0m \033[35m请重装系统后重新运行此脚本 (CentOS7.0 - CentOS7.6)！\033[0m\n");
		exit(0);
	}
	
	if (!access("/usr/bin/rm",0)){
        //printf("文件状态正常！");
    }else{
		printf("\n\033[33m系统完整性状态:\033[0m \033[34m效验失败-4\033[0m \033[31m[X]\033[0m \033[35m请重装系统后重新运行此脚本 (CentOS7.0 - CentOS7.6)！\033[0m\n");
		exit(0);
	}
	
	if (!access("/usr/bin/cat",0)){
        //printf("文件状态正常！");
    }else{
		printf("\n\033[33m系统完整性状态:\033[0m \033[34m效验失败-5\033[0m \033[31m[X]\033[0m \033[35m请重装系统后重新运行此脚本 (CentOS7.0 - CentOS7.6)！\033[0m\n");
		exit(0);
	}
	
	if (!access("/usr/bin/cd",0)){
        //printf("文件状态正常！");
    }else{
		printf("\n\033[33m系统完整性状态:\033[0m \033[34m效验失败-6\033[0m \033[31m[X]\033[0m \033[35m请重装系统后重新运行此脚本 (CentOS7.0 - CentOS7.6)！\033[0m\n");
		exit(0);
	}
	
	if (!access("/usr/bin/chmod",0)){
        //printf("文件状态正常！");
    }else{
		printf("\n\033[33m系统完整性状态:\033[0m \033[34m效验失败-7\033[0m \033[31m[X]\033[0m \033[35m请重装系统后重新运行此脚本 (CentOS7.0 - CentOS7.6)！\033[0m\n");
		exit(0);
	}
	
	if (!access("/usr/bin/ps",0)){
        //printf("文件状态正常！");
    }else{
		printf("\n\033[33m系统完整性状态:\033[0m \033[34m效验失败-8\033[0m \033[31m[X]\033[0m \033[35m请重装系统后重新运行此脚本 (CentOS7.0 - CentOS7.6)！\033[0m\n");
		exit(0);
	}
	
	printf("\n\033[33m系统状态:\033[0m \033[34m正常\033[0m \033[32m[ √]\033[0m \033[35m系统状态正常！\033[0m\n");
}

void Menu()
{
	if (!access("/usr/bin/mysql",0)){
        printf("\n\033[33m系统检测到您已安装流控系统，继续安装会导致安装失败，请重装系统后重新执行此脚本 (CentOS7.0 - CentOS7.6)！\033[0m\n");
		exit(0);
    }else{
		//printf("\n\033[33m未安装数据库！\033[0m\n");
	}
	char Download_Host_Base64[100];
	sprintf(Download_Host_Base64,"echo %s | base64 -d",Download_Host);
	char Download_Host_Base64_1[100];
	strcpy(Download_Host_Base64_1,cmd_system(Download_Host_Base64));
	char Get_IP_1[500];
	sprintf(Get_IP_1,"curl -s %s",Get_IP);
	char IP[500];
	strcpy(IP,cmd_system(Get_IP_1));
	char Random_MySQL_Pass[100];
	strcpy(Random_MySQL_Pass,cmd_system("date +%s%N | md5sum | head -c 20"));
	char Download_YUM_Base64[100];
	sprintf(Download_YUM_Base64,"echo %s | base64 -d",Download_YUM);
	char Download_YUM_Base64_1[100];
	strcpy(Download_YUM_Base64_1,cmd_system(Download_YUM_Base64));
	char Cat_LocalPass[100];
	sprintf(Cat_LocalPass,"cat %s",Local_Pass_Config);
	setbuf(stdout,NULL);
	system("clear");
	printf("\n\033[1;42;37m尊敬的用户您好，搭建 聚力流控™ 系统之前请您先填写以下信息，如不会填写请直接回车即可！\033[0m\n");
	
	
	sleep(1);
	printf("\n\033[36m请设置后台账号(默认admin): \033[0m");
	char JuLi_JuLi_User[20];
	gets(JuLi_JuLi_User);
	if (strcmp(JuLi_JuLi_User,"")==0){
		strcpy(JuLi_JuLi_User,"admin");
		printf("\n\033[36m已设置后台账号为:\033[0m \033[32m%s\033[0m\n",JuLi_JuLi_User);
	}else{
		printf("\n\033[36m已设置后台账号为:\033[0m \033[32m%s\033[0m\n",JuLi_JuLi_User);
	}
	
	
	sleep(1);
	printf("\n\033[36m请设置后台密码(默认admin): \033[0m");
	char JuLi_JuLi_Pass[20];
	gets(JuLi_JuLi_Pass);
	if (strcmp(JuLi_JuLi_Pass,"")==0){
		strcpy(JuLi_JuLi_Pass,"admin");
		printf("\n\033[36m已设置后台密码为:\033[0m \033[32m%s\033[0m\n",JuLi_JuLi_Pass);
	}else{
		printf("\n\033[36m已设置后台密码为:\033[0m \033[32m%s\033[0m\n",JuLi_JuLi_Pass);
	}
	
	
	sleep(1);
	printf("\n\033[36m请设置后台端口(默认7878): \033[0m");
	char JuLi_Apache_Port[20];
	gets(JuLi_Apache_Port);
	if (strcmp(JuLi_Apache_Port,"")==0){
		strcpy(JuLi_Apache_Port,"7878");
		printf("\n\033[36m已设置后台端口为:\033[0m \033[32m%s\033[0m\n",JuLi_Apache_Port);
	}else{
		printf("\n\033[36m已设置后台端口为:\033[0m \033[32m%s\033[0m\n",JuLi_Apache_Port);
	}
	
	
	sleep(1);
	printf("\n\033[36m请设置数据库密码(默认随机): \033[0m");
	char JuLi_MySQL_Pass[20];
	gets(JuLi_MySQL_Pass);
	if (strcmp(JuLi_MySQL_Pass,"")==0){
		strcpy(JuLi_MySQL_Pass,Random_MySQL_Pass);
		printf("\n\033[36m已设置数据库密码为:\033[0m \033[32m%s\033[0m\n",JuLi_MySQL_Pass);
	}else{
		printf("\n\033[36m已设置数据库密码为:\033[0m \033[32m%s\033[0m\n",JuLi_MySQL_Pass);
	}
	
	
	sleep(1);
	printf("\n\033[36m请设置APP名称(默认聚力流控): \033[0m");
	char JuLi_APP_Name[20];
	gets(JuLi_APP_Name);
	if (strcmp(JuLi_APP_Name,"")==0){
		strcpy(JuLi_APP_Name,"聚力流控");
		printf("\n\033[36m已设置APP名称为:\033[0m \033[32m%s\033[0m\n",JuLi_APP_Name);
	}else{
		printf("\n\033[36m已设置APP名称为:\033[0m \033[32m%s\033[0m\n",JuLi_APP_Name);
		
	}
	
	
	sleep(1);
	printf("\n\033[36m请输入您当前SSH端口号(默认22): \033[0m");
	char JuLi_SSH_Port[20];
	gets(JuLi_SSH_Port);
	if (strcmp(JuLi_SSH_Port,"")==0){
		strcpy(JuLi_SSH_Port,"22");
		printf("\n\033[36m已输入当前SSH端口号为:\033[0m \033[32m%s\033[0m\n",JuLi_SSH_Port);
	}else{
		printf("\n\033[36m已输入当前SSH端口号为:\033[0m \033[32m%s\033[0m\n",JuLi_SSH_Port);
		
	}
	
	
	sleep(1);
	printf("\n");
	printf("\033[31m请稍等...\033[0m\n");
	sleep(3);
	printf("\n\033[1;5;33m所有信息已收集完成！正在准备为您安装聚力流控™ 系统！\033[0m\n");
	sleep(5);
	setbuf(stdout,NULL);
	system("clear");
	printf("\n\033[36m更新时间:\033[0m \033[31m%s\033[0m \033[36m聚力流控™ V4.6 系统极速安装 2-5 分钟完成安装.......\033[0m\n\n                        \033[32m[正在极速安装中请等待]\033[0m\n",Version);
	sleep(3);
	
	printf("\n\033[36m正在初始化环境...\033[0m\n");
	//Build_Check();
	checkcode(runshell(2,Backup_YUM));
	checkcode(runshell(2,Delete_EPEL));
	char Install_YUM[100];
	sprintf(Install_YUM,"wget -O /etc/yum.repos.d/CentOS-Base.repo %s >/dev/null 2>&1",Download_YUM_Base64_1);
	checkcode(runshell(2,Install_YUM));
	char Install_JuLi_PHP[100];
	sprintf(Install_JuLi_PHP,"wget -O /etc/yum.repos.d/%s \"%s%s\" >/dev/null 2>&1",Download_PHP_Name,Download_Host_Base64_1,Download_PHP);
	checkcode(runshell(2,Install_JuLi_PHP));
	char Install_JuLi_EPEL[100];
	sprintf(Install_JuLi_EPEL,"wget -O /etc/yum.repos.d/%s \"%s%s\" >/dev/null 2>&1",Download_EPEL_Name,Download_Host_Base64_1,Download_EPEL);
	checkcode(runshell(2,Install_JuLi_EPEL));
	char Install_JuLi_EPEL_01[100];
	sprintf(Install_JuLi_EPEL_01,"wget -O /etc/yum.repos.d/%s \"%s%s\" >/dev/null 2>&1",Download_EPEL_01_Name,Download_Host_Base64_1,Download_EPEL_01);
	checkcode(runshell(2,Install_JuLi_EPEL_01));
	checkcode(runshell(2,Clean_All));
	checkcode(runshell(2,Makecache));
	
	printf("\033[36m正在关闭SELinux...\033[0m\n");
	//Build_Check();
	checkcode(runshell(1,Install_SELinux));
	checkcode(runshell(2,SELinux_Off));
	checkcode(runshell(2,SELinux_Config_Off));
	
	printf("\033[36m正在配置防火墙...\033[0m\n");
	//Build_Check();
	checkcode(runshell(2,Stop_Firewalld));
	checkcode(runshell(2,Disable_Firewalld));
	checkcode(runshell(2,"systemctl stop iptables.service >/dev/null 2>&1"));
	checkcode(runshell(1,Install_Iptables));
	checkcode(runshell(2,Start_Iptables));
	checkcode(runshell(2,Iptables_F));
	checkcode(runshell(2,Iptables_Save));
	checkcode(runshell(2,Restart_Iptables));
	checkcode(runshell(2,Iptables_01));
	checkcode(runshell(2,Iptables_02));
	checkcode(runshell(2,Iptables_03));
	checkcode(runshell(2,Iptables_04));
	checkcode(runshell(2,Iptables_05));
	checkcode(runshell(2,Iptables_06));
	checkcode(runshell(2,Iptables_07));
	checkcode(runshell(2,Iptables_08));
	checkcode(runshell(2,Iptables_09));
	checkcode(runshell(2,Iptables_10));
	checkcode(runshell(2,Iptables_11));
	checkcode(runshell(2,Iptables_12));
	checkcode(runshell(2,Iptables_13));
	checkcode(runshell(2,Iptables_14));
	checkcode(runshell(2,Iptables_15));
	checkcode(runshell(2,Iptables_16));
	checkcode(runshell(2,Iptables_17));
	checkcode(runshell(2,Iptables_18));
	checkcode(runshell(2,Iptables_19));
	checkcode(runshell(2,Iptables_20));
	checkcode(runshell(2,Iptables_21));
	checkcode(runshell(2,Iptables_22));
	checkcode(runshell(2,Iptables_23));
	checkcode(runshell(2,Iptables_24));
	checkcode(runshell(2,Iptables_25));
	checkcode(runshell(2,Iptables_26));
	checkcode(runshell(2,Iptables_27));
	checkcode(runshell(2,Iptables_28));
	checkcode(runshell(2,Iptables_29));
	checkcode(runshell(2,Iptables_30));
	checkcode(runshell(2,Iptables_31));
	checkcode(runshell(2,Iptables_32));
	checkcode(runshell(2,Iptables_33));
	checkcode(runshell(2,Iptables_34));
	checkcode(runshell(2,Iptables_35));
	checkcode(runshell(2,Iptables_36));
	checkcode(runshell(2,Iptables_37));
	checkcode(runshell(2,Iptables_38));
	//checkcode(runshell(2,Iptables_39));
	checkcode(runshell(2,Iptables_40));
	char JuLi_Apache_Port_01[200];
	sprintf(JuLi_Apache_Port_01,"iptables -A INPUT -p tcp -m tcp --dport %s -j ACCEPT",JuLi_Apache_Port);
	checkcode(runshell(2,JuLi_Apache_Port_01));
	char JuLi_SSH_Port_01[200];
	sprintf(JuLi_SSH_Port_01,"iptables -A INPUT -p tcp -m tcp --dport %s -j ACCEPT",JuLi_SSH_Port);
	checkcode(runshell(2,JuLi_SSH_Port_01));
	checkcode(runshell(2,Iptables_Save));
	checkcode(runshell(2,Restart_Iptables));
	//checkcode(runshell(2,Write_Host_Name));
	
	printf("\033[36m正在配置Sysctl环境...\033[0m\n");
	//Build_Check();
	checkcode(runshell(2,"rm -rf /etc/sysctl.conf"));
	char Sysctl_01[100];
	sprintf(Sysctl_01,"wget -O /etc/sysctl.conf \"%s%s\" >/dev/null 2>&1",Download_Host_Base64_1,Download_Sysctl);
	checkcode(runshell(2,Sysctl_01));
	checkcode(runshell(2,"chmod -R 0777 /etc/sysctl.conf"));
	checkcode(runshell(2,"sysctl -p /etc/sysctl.conf >/dev/null 2>&1"));
	
	printf("\033[36m正在安装系统环境...\033[0m\n");
	//Build_Check();
	checkcode(runshell(1,Install_System));
	
	printf("\033[36m正在安装免流环境...\033[0m\n");
	//Build_Check();
	checkcode(runshell(1,Install_ml));
	char OpenVPN_liblz4[200];
	sprintf(OpenVPN_liblz4,"rpm -Uvh \"%s%s\" %s >/dev/null 2>&1",Download_Host_Base64_1,OpenVPN_liblz4_RPM,Force_Install_RPM);
	checkcode(runshell(2,OpenVPN_liblz4));
	char OpenVPN_246[200];
	sprintf(OpenVPN_246,"rpm -Uvh \"%s%s\" %s >/dev/null 2>&1",Download_Host_Base64_1,OpenVPN_RPM,Force_Install_RPM);
	checkcode(runshell(2,OpenVPN_246));
	
	printf("\033[36m正在安装聚力独家极速PHP环境...\033[0m\n");
	//Build_Check();
	checkcode(runshell(1,Install_PHP7));
	
	printf("\033[36m正在配置MariaDB环境...\033[0m\n");
	//Build_Check();
	checkcode(runshell(2,Start_MariaDB));
	char MySQL_01[100];
	sprintf(MySQL_01,"mysqladmin -uroot password \"%s\"\nmysql -uroot -p%s -e \"create database vpndata;\"",JuLi_MySQL_Pass,JuLi_MySQL_Pass);
	checkcode(runshell(2,MySQL_01));
	checkcode(runshell(2,Restart_MariaDB));
	
	printf("\033[36m正在配置Apache环境...\033[0m\n");
	//Build_Check();
	char Apache_01[300];
	sprintf(Apache_01,"sed -i \"s/#ServerName www.example.com:80/ServerName localhost:%s/g\" /etc/httpd/conf/httpd.conf\nsed -i \"s/Listen 80/Listen %s/g\" /etc/httpd/conf/httpd.conf",JuLi_Apache_Port,JuLi_Apache_Port);
	checkcode(runshell(2,Apache_01));
	checkcode(runshell(2,Start_Apache));
	
	printf("\033[36m正在配置DNS环境...\033[0m\n");
	//Build_Check();
	checkcode(runshell(2,"rm -rf /etc/dnsmasq.conf"));
	char DNS_01[100];
	sprintf(DNS_01,"wget -O /etc/dnsmasq.conf \"%s%s\" >/dev/null 2>&1",Download_Host_Base64_1,Download_DNS);
	checkcode(runshell(2,DNS_01));
	checkcode(runshell(2,"chmod 0777 /etc/dnsmasq.conf"));
	checkcode(runshell(2,Start_DNS));
	
	printf("\033[36m正在配置OpenVPN环境...\033[0m\n");
	//Build_Check();
	char OpenVPN_01[100];
	sprintf(OpenVPN_01,"wget -O /etc/openvpn/openvpn.zip \"%s%s\" >/dev/null 2>&1",Download_Host_Base64_1,Download_OpenVPN);
	checkcode(runshell(2,OpenVPN_01));
	setbuf(stdout,NULL);
	system("cd /etc/openvpn && unzip -o openvpn.zip >/dev/null 2>&1");
	checkcode(runshell(2,"rm -rf /etc/openvpn/openvpn.zip"));
	checkcode(runshell(2,"chmod 0777 -R /etc/openvpn"));
	char OpenVPN_02[100];
	sprintf(OpenVPN_02,"sed -i \"s/newpass/%s/g\" /etc/openvpn/auth_config.conf\nsed -i \"s/服务器IP/%s/g\" /etc/openvpn/auth_config.conf",JuLi_MySQL_Pass,IP);
	checkcode(runshell(2,OpenVPN_02));
	
	printf("\033[36m正在配置Crond环境...\033[0m\n");
	//Build_Check();
	checkcode(runshell(2,Start_Crond));
	checkcode(runshell(2,"crontab -l > /tmp/crontab.$$\necho \"*/60 * * * * /etc/openvpn/sqlbackup\" >> /tmp/crontab.$$\ncrontab /tmp/crontab.$$"));
	checkcode(runshell(2,Restart_Crond));
	
	printf("\033[36m正在安装依赖文件...\033[0m\n");
	//Build_Check();
	checkcode(runshell(2,"mkdir /etc/rate.d/ >/dev/null 2>&1"));
	checkcode(runshell(2,"chmod -R 0777 /etc/rate.d/"));
	char Dependency_file_01[100];
	sprintf(Dependency_file_01,"wget -O /root/res.zip \"%s%s\" >/dev/null 2>&1",Download_Host_Base64_1,Download_Res);
	checkcode(runshell(2,Dependency_file_01));
	setbuf(stdout,NULL);
	system("cd /root && unzip -o res.zip >/dev/null 2>&1");
	checkcode(runshell(2,"chmod -R 0777 /root"));
	checkcode(runshell(2,"rm -rf /root/res.zip"));
	checkcode(runshell(2,"mv /root/res/fas.service /lib/systemd/system/fas.service"));
	checkcode(runshell(2,"chmod -R 0777 /lib/systemd/system/fas.service"));
	checkcode(runshell(2,Enable_JuLi));
	char Dependency_file_02[100];
	sprintf(Dependency_file_02,"wget -O /bin/bin.zip \"%s%s\" >/dev/null 2>&1",Download_Host_Base64_1,Download_Bin);
	checkcode(runshell(2,Dependency_file_02));
	setbuf(stdout,NULL);
	system("cd /bin && unzip -o bin.zip >/dev/null 2>&1");
	checkcode(runshell(2,"rm -rf /bin/bin.zip"));
	checkcode(runshell(2,"chmod -R 0777 /bin"));
	checkcode(runshell(2,"echo \"#聚力流控™ 系统自定义屏蔽host文件\n\">>/etc/hyx_host"));
	checkcode(runshell(2,"chmod 0777 /etc/hyx_host"));
	
	printf("\033[36m正在安装聚力流控_WEB控制面板...\033[0m\n");
	//Build_Check();
	checkcode(runshell(2,"rm -rf /var/www/html"));
	char JULI_WEB_01[100];
	sprintf(JULI_WEB_01,"wget -O /var/www/juli_web.zip \"%s%s\" >/dev/null 2>&1",Download_Host_Base64_1,Download_WEB);
	checkcode(runshell(2,JULI_WEB_01));
	setbuf(stdout,NULL);
	system("cd /var/www && unzip -o juli_web.zip >/dev/null 2>&1");
	checkcode(runshell(2,"rm -rf /var/www/juli_web.zip"));
	checkcode(runshell(2,"chmod 0777 -R /var/www/*"));
	char JULI_WEB_02[100];
	sprintf(JULI_WEB_02,"sed -i \"s/JuLi_User/\"%s\"/g\" /var/www/vpndata.sql\nsed -i \"s/JuLi_Pass/\"%s\"/g\" /var/www/vpndata.sql\nsed -i \"s/服务器IP/\"%s\"/g\" /var/www/vpndata.sql\nsed -i \"s/服务器端口/\"%s\"/g\" /var/www/vpndata.sql\nmysql -uroot -p%s vpndata < /var/www/vpndata.sql\nrm -rf /var/www/vpndata.sql\nsed -i \"s/newpass/\"%s\"/g\" /var/www/html/config.php\necho \"$RANDOM$RANDOM\">/var/www/auth_key.access",JuLi_JuLi_User,JuLi_JuLi_Pass,IP,JuLi_Apache_Port,JuLi_MySQL_Pass,JuLi_MySQL_Pass);
	checkcode(runshell(2,JULI_WEB_02));
	char JULI_WEB_03[100];
	sprintf(JULI_WEB_03,"sed -i \"s/聚力网络/%s/g\" /var/www/html/app/index.php\nsed -i \"s/聚力网络/%s/g\" /var/www/html/web/index.html",JuLi_APP_Name,JuLi_APP_Name);
	checkcode(runshell(2,JULI_WEB_03));
	
	printf("\033[36m正在制作APP...\033[0m\n");
	//Build_Check();
	char JULI_APP_01[500];
	sprintf(JULI_APP_01,"wget -O fas.apk \"%s%s\" >/dev/null 2>&1\nwget -O apktool.jar \"%s%s\" >/dev/null 2>&1\njava -jar apktool.jar d fas.apk >/dev/null 2>&1\nrm -rf fas.apk\nsed -i 's/demo.dingd.cn:80/'%s:%s'/g' `grep demo.dingd.cn:80 -rl /root/fas/smali/net/openvpn/openvpn/` >/dev/null 2>&1\nsed -i 's/叮咚流量卫士/'%s'/g' \"/root/fas/res/values/strings.xml\"\nsed -i 's/net.dingd.vpn/'%s'/g' \"/root/fas/AndroidManifest.xml\"\njava -jar apktool.jar b fas >/dev/null 2>&1\nwget -O signer.zip \"%s%s\" >/dev/null 2>&1\nunzip -o signer.zip >/dev/null 2>&1\nmv /root/fas/dist/fas.apk /root/fas.apk\njava -jar signapk.jar testkey.x509.pem testkey.pk8 /root/fas.apk /root/fas_sign.apk\nrm -rf /var/www/html/fasapp_by_hyx.apk\ncp -rf /root/fas_sign.apk /var/www/html/app/app.apk",Download_Host_Base64_1,Download_APP,Download_Host_Base64_1,Download_ApkTool,IP,JuLi_Apache_Port,JuLi_APP_Name,JuLi_APP_File,Download_Host_Base64_1,Download_Signed);
	checkcode(runshell(2,JULI_APP_01));
	checkcode(runshell(2,"rm -rf /root/fas\nrm -rf /root/apktool.jar\nrm -rf /root/fas.apk\nrm -rf /root/fas_sign.apk\nrm -rf /root/signapk.bat\nrm -rf /root/signapk.jar\nrm -rf /root/signer.zip\nrm -rf /root/test\nrm -rf /root/testkey.pk8\nrm -rf /root/testkey.x509.pem"));
	setbuf(stdout,NULL);
	system("clear");
	
	printf("\033[35m正在启动所有服务(遇到启动失败请重装系统或联系作者)...\033[0m\n");
	//Build_Check();
	sleep(5);
	printf("\n\033[33m尝试启动IptabLes服务...\033[0m\n");
	setbuf(stdout,NULL);
	system("systemctl restart iptables.service\n	if [[ $? -eq 0 ]];then\n		echo -e \"\033[35mIPtables启动成功！\033[0m\n\"\n	else\n		echo -e \"\033[35mIPtables启动失败！\033[0m\n\"\n	fi");
	sleep(2);
	printf("\033[33m尝试启动MariaDB服务...\033[0m\n");
	setbuf(stdout,NULL);
	system("systemctl restart mariadb.service\n	if [[ $? -eq 0 ]];then\n		echo -e \"\033[35mMariaDB启动成功！\033[0m\n\"\n	else\n		echo -e \"\033[35mMariaDB启动失败！\033[0m\n\"\n	fi");
	sleep(2);
	printf("\033[33m尝试启动Apache服务...\033[0m\n");
	setbuf(stdout,NULL);
	system("systemctl restart httpd.service\n	if [[ $? -eq 0 ]];then\n		echo -e \"\033[35mApache启动成功！\033[0m\n\"\n	else\n		echo -e \"\033[35mApache启动失败！\033[0m\n\"\n	fi");
	sleep(2);
	printf("\033[33m尝试启动DNS服务...\033[0m\n");
	setbuf(stdout,NULL);
	system("systemctl restart dnsmasq.service\n	if [[ $? -eq 0 ]];then\n		echo -e \"\033[35mDNS启动成功！\033[0m\n\"\n	else\n		echo -e \"\033[35mDNS启动失败！\033[0m\n\"\n	fi");
	sleep(2);
	printf("\033[33m尝试启动Crond服务...\033[0m\n");
	setbuf(stdout,NULL);
	system("systemctl restart crond.service\n	if [[ $? -eq 0 ]];then\n		echo -e \"\033[35mCrond启动成功！\033[0m\n\"\n	else\n		echo -e \"\033[35mCrond启动失败！\033[0m\n\"\n	fi");
	sleep(2);
	printf("\033[33m尝试启动OpenVPN_TCP1服务...\033[0m\n");
	setbuf(stdout,NULL);
	system("systemctl restart openvpn@server1194.service\n	if [[ $? -eq 0 ]];then\n		echo -e \"\033[35mOpenVPN_TCP1启动成功！\033[0m\n\"\n	else\n		echo -e \"\033[35mOpenVPN_TCP1启动失败！\033[0m\n\"\n	fi");
	sleep(2);
	printf("\033[33m尝试启动OpenVPN_TCP2服务...\033[0m\n");
	setbuf(stdout,NULL);
	system("systemctl restart openvpn@server1195.service\n	if [[ $? -eq 0 ]];then\n		echo -e \"\033[35mOpenVPN_TCP2启动成功！\033[0m\n\"\n	else\n		echo -e \"\033[35mOpenVPN_TCP2启动失败！\033[0m\n\"\n	fi");
	sleep(2);
	printf("\033[33m尝试启动OpenVPN_TCP3服务...\033[0m\n");
	setbuf(stdout,NULL);
	system("systemctl restart openvpn@server1196.service\n	if [[ $? -eq 0 ]];then\n		echo -e \"\033[35mOpenVPN_TCP3启动成功！\033[0m\n\"\n	else\n		echo -e \"\033[35mOpenVPN_TCP3启动失败！\033[0m\n\"\n	fi");
	sleep(2);
	printf("\033[33m尝试启动OpenVPN_TCP4服务...\033[0m\n");
	setbuf(stdout,NULL);
	system("systemctl restart openvpn@server1197.service\n	if [[ $? -eq 0 ]];then\n		echo -e \"\033[35mOpenVPN_TCP4启动成功！\033[0m\n\"\n	else\n		echo -e \"\033[35mOpenVPN_TCP4启动失败！\033[0m\n\"\n	fi");
	sleep(2);
	printf("\033[33m尝试启动OpenVPN_UDP服务...\033[0m\n");
	setbuf(stdout,NULL);
	system("systemctl restart openvpn@server-udp.service\n	if [[ $? -eq 0 ]];then\n		echo -e \"\033[35mOpenVPN_UDP启动成功！\033[0m\n\"\n	else\n		echo -e \"\033[35mOpenVPN_UDP启动失败！\033[0m\n\"\n	fi");
	sleep(2);
	printf("\033[33m尝试启动聚力流控™服务...\033[0m\n");
	setbuf(stdout,NULL);
	system("systemctl restart fas.service\n	if [[ $? -eq 0 ]];then\n		echo -e \"\033[35m聚力流控服务启动成功！\033[0m\n\"\n	else\n		echo -e \"\033[35m聚力流控服务启动失败！\033[0m\n\"\n	fi");
	sleep(2);
	printf("\033[33m正在执行最后的操作...\033[0m\n");
	//Build_Check();
	sleep(2);
	checkcode(runshell(2,Dhclient));
	checkcode(runshell(2,"unsql >/dev/null 2>&1"));
	checkcode(runshell(2,Restart_VPN));
	checkcode(runshell(2,"echo \"vpn restart\">> /etc/rc.d/rc.local"));
	checkcode(runshell(2,"chmod +x /etc/rc.d/rc.local"));
	sleep(2);
	char LocalPass[100];
	strcpy(LocalPass,cmd_system(Cat_LocalPass));
	setbuf(stdout,NULL);
	system("clear");
	printf("\n\033[36m--------------------------------------------------------------------------\033[0m");
	printf("\n\033[36m                   聚力网络科技 聚力流控™ 系统已安装完成！             \033[0m");
	printf("\n\033[36m                           以下是您服务器信息！                           \033[0m");
	printf("\n\033[36m                用户中心: http://%s:%s/%s/             \033[0m",IP,JuLi_Apache_Port,WEB_IOS);
	printf("\n\033[36m                后台管理: http://%s:%s/%s/             \033[0m",IP,JuLi_Apache_Port,WEB_Admin);
	printf("\n\033[36m                后台账户: %s  后台密码: %s             \033[0m",JuLi_JuLi_User,JuLi_JuLi_Pass);
	printf("\n\033[36m                本地密码: %s             \033[0m",LocalPass);
	printf("\n\033[36m                数据库管理: http://%s:%s/%s/             \033[0m",IP,JuLi_Apache_Port,WEB_MySQL);
	printf("\n\033[36m                数据库账户: %s  数据库密码: %s             \033[0m",MySQL_Name,JuLi_MySQL_Pass);
	printf("\n\033[36m                代理后台: http://%s:%s/%s/             \033[0m",IP,JuLi_Apache_Port,WEB_Agent);
	printf("\n\033[36m                APP下载地址: http://%s:%s/%s             \033[0m",IP,JuLi_Apache_Port,Make_APP_Name);
	printf("\n\033[36m                WEB引导页面: http://%s:%s/%s             \033[0m",IP,JuLi_Apache_Port,WEB_Name);
	printf("\n\033[36m--------------------------------------------------------------------------\033[0m");
	printf("\n\033[36m  常用指令(请在SSH界面执行):             \033[0m");
	printf("\n\033[36m               重启VPN: %s     流控后台开启: %s             \033[0m",Restart_VPN,Open_lock);
	printf("\n\033[36m               启动VPN: %s       流控后台关闭: %s             \033[0m",Start_VPN,Close_lock);
	printf("\n\033[36m               停止VPN: %s        数据库后台开启: %s             \033[0m",Stop_VPN,Open_Sql);
	printf("\n\033[36m               开任意端口: %s         数据库后台关闭: %s             \033[0m",Open_Port,Close_Sql);
	printf("\n\033[36m            温馨提醒: 网页数据库打不开的请在SSH界面输入 %s 就好啦！    \033[0m",Open_Sql);
	printf("\n\033[36m--------------------------------------------------------------------------\033[0m");
	printf("\n\033[36m            数据库 %s 表 60分钟自动备份，备份目录在%s/             \033[0m",JuLi_MySql_Name,Backup_Config);
	printf("\n\033[36m            数据库手动备份命令：backup             \033[0m");
	printf("\n\033[36m--------------------------------------------------------------------------\033[0m");
	printf("\n\033[36m  聚力流控™开发作者: 何以潇 QQ: 1744744222  如需帮助，请联系开发作者！    \033[0m");
	printf("\n\033[36m  聚力网络流控交流群: 798226070     聚力网络流控售后群: 816468465         \033[0m");
	printf("\n\033[36m--------------------------------------------------------------------------\033[0m\n");
	exit(0);
}
char* cmd_system(char* command)
{
    memset(buff, 0, sizeof(buff));
    return shellcmd(command, buff, sizeof(buff));
}