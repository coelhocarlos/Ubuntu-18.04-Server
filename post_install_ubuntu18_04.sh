#
#Date - 06/22/2018
#Created by Carlos Coelho
#Pos Install Ubuntu server 18.04
#
BLACK=`tput setaf 0`
RED=`tput setaf 1`
GREEN=`tput setaf 2`
YELLOW=`tput setaf 3`
BLUE=`tput setaf 4`
MAGENTA=`tput setaf 5`
CYAN=`tput setaf 6`
WHITE=`tput setaf 7`
BOLD=`tput bold`
RESET=`tput sgr0`

#tput setab 7
################################################################################
#                               Change root pass                               #
################################################################################
sudo whoami
sudo -i
sudo passwd
################################################################################
#                               Start Script                                   #
################################################################################

tput setab 7
echo -e  ${YELLOW} 
echo -e " ${RED} CHECK UPDATES ..."
echo -e  ${BLACK} 
sudo apt-get update && apt-get -y upgrade &&  apt-get -y dist-upgrade
echo -e  ${WHITE}
tput reset
################################################################################
#                                 LIBRARIES INSTALL                            #
################################################################################

echo -e "${RED} LIBRARIES INSTALL"
echo -e  ${WHITE}
   sudo apt install -y  wget
   sudo apt install -y  gcc wget
   sudo apt install -y  git wget
   sudo apt install -y  make wget
   sudo apt install -y  touch wget
   sudo apt install -y  ntfs-3g wget
   sudo apt install -y  testdisk wget
   sudo apt install -y  glances wget
   sudo apt install -y  iptraf wget
   sudo apt install -y  genisoimage wget
   sudo apt install -y  wimtools -wget
   sudo apt install -y  cabextract -wget
ln -s /usr/bin/genisoimage /usr/bin/mkisof
echo -e ${CYAN}"LIBRARIES INSTALLED --${GREEN} Successfull"
echo -e ""
echo -e ""
echo -e ""
################################################################################
#                         MOUNT HD EXTERN                                      #
################################################################################
#echo -e "${RED} MOUNT HD EXTERN"
#echo -e  ${WHITE}

#mkdir /media/hd2000
#mount -t ntfs-3g /dev/sdb1 /media/hd160
#mount -t ntfs-3g /dev/sdb1 /media/hd2000
#echo -e ${CYAN}"MOUNTED AS /media/hd2000 --${GREEN} Successfull"
#echo -e ""
#echo -e ""
#echo -e ""
################################################################################
#                           SCRIPTS                                            #
################################################################################
 echo -e "${YELLOW} ADDING SCRIPTS"
  echo -e  ${WHITE}
cd
sudo mkdir ~/.scripts
cd ~/.scripts
sudo wget https://raw.githubusercontent.com/coelhocarlos/meganz/master/megasend.sh
sudo wget https://raw.githubusercontent.com/coelhocarlos/sqldump/master/mysqldump.sh
sudo wget https://raw.githubusercontent.com/coelhocarlos/DebianScripts/master/duck.sh
sudo chmod +x megasend.sh
sudo chmod +x mysqldump.sh
sudo chmod +x duck.sh
sudo touch /var/spool/cron/crontabs/root
sudo echo "* 23 * * * ~/.scripts/mysqldump.sh #Mysql backup" >>/var/spool/cron/crontabs/root
sudo echo "@daily ~/.scripts/megasend.sh" >> /var/spool/cron/crontabs/root
sudo echo "5 * * * * ~/.scripts/duck.sh" >> /var/spool/cron/crontabs/root
 echo -e "${CYAN} SCRIPTS ADDED ${GREEN}Successfull" 
cd 
cd downloads/
echo -e ""
echo -e ""
echo -e ""
################################################################################
#                                   USERS                                      #
################################################################################
echo -e  "${YELLOW} ADD USERS"
echo -e  ${WHITE}
sudo adduser pedro
sudo adduser andre
sudo usermod -aG sudo pedro
sudo usermod -aG sudo andre
echo -e " ${CYAN} users added${GREEN}Successfull"
################################################################################
#                           MEGA UPLOADER                                      #
################################################################################
 echo -e "${YELLOW} MEGATOOLS INSTALL"
    echo -e  "${WHITE}"
    sudo apt install megatools wget
    cd 
    sudo touch ~/.megarc
    echo "[Login]" >> ~/.megarc
    echo "Username = carloscoelho_@msn.com" >> ~/.megarc
    echo "Password = " >> ~/.megarc
 echo -e "${CYAN} MEGATOOLS  INSTALLED ${GREEN}Successfull"   
 echo -e ""
echo -e ""
echo -e ""

################################################################################
#                                  Webmin                                      #
################################################################################

echo -e  "{$YELLOW} WEBMIN INSTALL"
echo -e  ${WHITE}
   sudo apt updatesudo apt install software-properties-common apt-transport-https wget
   sudo wget -q http://www.webmin.com/jcameron-key.asc -O- | sudo apt-key add -
   sudo add-apt-repository "deb [arch=amd64] http://download.webmin.com/download/repository sarge contrib"
   sudo apt -y install webmin
echo -e ${CYAN}"WEBMIN   ${GREEN}INSTALLED Successful"
echo -e ""
echo -e ""
echo -e ""
################################################################################
#                                   PHP                                        #
################################################################################

echo -e "${YELLOW} PHP 7.2 INSTALL"
echo -e  ${WHITE} 
    sudo apt install -y php7.2 libapache2-mod-php7.2 wget
    sudo pecl channel-update pecl.php.net
    sudo pecl install mcrypt-1.0.1
    sudo apt install php-dev libmcrypt-dev php-pear
    sudo apt-get -y install php7.2-mysql php7.2-curl php-fpm php7.2-gd php7.2-intl php-pear php-imagick php7.2-imap php-memcache  php7.2-pspell php7.2-recode php7.2-sqlite3 php7.2-tidy php7.2-xmlrpc php7.2-xsl php7.2-mbstring php-gettext
    sudo wget http://archive.ubuntu.com/ubuntu/pool/universe/x/xdebug/php-xdebug_2.6.0-0ubuntu1_amd64.deb
    sudo dpkg -i php-xdebug_2.6.0-0ubuntu1_amd64.deb
    sudo systemctl restart apache2 
    sudo apt-get -y install php7.2-opcache php-apcu
    sudo systemctl restart apache2 
    sudo a2enmod ssl 
    sudo systemctl restart apache2
    sudo a2ensite default-ssl
    sudo systemctl restart apache2
echo -e "${CYAN} PHP 7.2 INSTALLED ${GREEN}Successfull"
echo -e ""
echo -e ""
echo -e ""
################################################################################
#                                   Apache SSL                                 #
################################################################################

echo -e "${YELLOW} APACHE INSTALL"
echo -e ${WHITE}
    sudo apt install -y apache2 apache2-utils libapache2-mod-php wget
   
    sudo a2enmod auth_digest ssl reqtimeout
    #sudo ufw app list 
    
    echo "Timeout 30" >> /etc/apache2/apache2.conf
    echo "ServerSignature Off" >> /etc/apache2/apache2.conf
    echo "ServerTokens Prod" >> /etc/apache2/apache2.conf
    
    sudo mkdir -p /home/zombie/www/secure
    sudo mkdir -p /home/zombie/www/server 
    sudo mkdir -p /home/zombie/www/public
    
    sudo chown -R www-data:www-data
    sudo chown -R zombie:zombie /home/zombie/www/html 
    sudo chown -R zombie:zombie /home/zombie/www/secure 
    sudo chown -R zombie:zombie /home/zombie/www/server 
    sudo chown -R zombie:zombie /home/zombie/www/public 

    sudo chmod -R 755 /home/zombie/www/html
    sudo chmod -R 755 /home/zombie/www/public
    sudo chmod -R 755 /home/zombie/www/server
    
    sudo systemctl restart apache2
    sudo mkdir /etc/apache2/ssl
    sudo openssl req -x509 -nodes -days 3650 -newkey rsa:2048 -keyout /etc/apache2/ssl/apache.pem -out /etc/apache2/ssl/apache.pem
    sudo chmod 600 /etc/apache2/ssl/apache.pem

    sudo a2ensite default-ssl
    sudo systemctl restart apache2

echo -e " ${CYAN} APACHE INSTALLED ${GREEN}Successfull"
echo -e ""
echo -e ""
echo -e ""
################################################################################
#                                   MYSQL                                      #
################################################################################

echo -e  "${YELLOW} MYSQL INSTALL"
echo -e  ${WHITE}
    sudo apt install -y mysql-server wget
    sudo apt install -y mysql-client wget
    #sudo mysql_secure_installation
    sudo systemctl restart mysql.service
echo -e "${CYAN} MYSQL INSTALLED ${GREEN}Successfull"
echo -e ""
echo -e ""
echo -e ""

################################################################################
#                                   SAMBA                                      #
################################################################################

echo -e  "${YELLOW} SAMBA INSTALL"
echo -e  ${WHITE}
        sudo apt install -y samba wget 
        #sudo cp /etc/samba/smb.conf /etc/samba/smb.conf_backup
        #touch /etc/samba/smb.conf
    
        sudo echo  "[Pxe]" >> /etc/samba/smb.conf
	sudo echo "path = /home/zombie/Servers/Share/tftp/" >> /etc/samba/smb.conf
	sudo echo "writeable = yes" >> /etc/samba/smb.conf
        sudo echo ""
        sudo echo "[Imagens]" >> /etc/samba/smb.conf
	sudo echo "writeable = yes" >> /etc/samba/smb.conf
	sudo echo "path = /home/zombie/images" >> /etc/samba/smb.conf
	sudo echo ""
        sudo echo "[Media]" >> /etc/samba/smb.conf
	sudo echo "writeable = yes" >> /etc/samba/smb.conf
	sudo echo "path = /home/zombie/Media" >> /etc/samba/smb.conf
        sudo echo ""
        sudo echo "[www zombie]" >> /etc/samba/smb.conf
	sudo echo "valid users = zombie" >> /etc/samba/smb.conf
	sudo echo "writeable = yes" >> /etc/samba/smb.conf
	sudo echo "path = /home/zombie/www" >> /etc/samba/smb.conf
        sudo echo ""
        sudo echo "[Code]" >> /etc/samba/smb.conf
	sudo echo "writeable = yes" >> /etc/samba/smb.conf
	sudo echo "valid users = zombie" >> /etc/samba/smb.conf
	sudo echo "path = /home/zombie/Server/Code" >> /etc/samba/smb.conf
        sudo echo ""
        sudo echo "[Games]" >> /etc/samba/smb.conf
	sudo echo "path = /home/zombie/Server/Games" >> /etc/samba/smb.conf
	sudo echo "writeable = yes" >> /etc/samba/smb.conf
	sudo echo "valid users = zombie" >> /etc/samba/smb.conf
	sudo echo ""
	sudo echo "[Push]" >> /etc/samba/smb.conf
	sudo echo "path = /home/zombie/Server/Downloads/torrent/torrent-push" >> /etc/samba/smb.conf
	sudo echo "writeable = yes" >> /etc/samba/smb.conf
	sudo echo ""
	sudo echo "[wwww Ubuntu]" >> /etc/samba/smb.conf
	sudo echo "path = /var/www/" >> /etc/samba/smb.conf
	sudo echo "writeable = yes" >> /etc/samba/smb.conf
	sudo echo "valid users = zombie" >> /etc/samba/smb.conf
	sudo echo ""
	sudo smbpasswd -a zombie
	sudo smbpasswd -a pedro
	sudo smbpasswd -a andre
	sudo service smbd restart
        #sudo bash -c 'grep -v -E "^#|^;" /etc/samba/smb.conf_backup | grep . > /etc/samba/smb.conf'
echo -e "${CYAN} SAMBA INSTALLED ${GREEN}Successfull"
echo -e ""
echo -e ""
echo -e ""
################################################################################
#                                   PHPMYADMIN                                 #
################################################################################

echo -e  "${YELLOW} PHPMYADMIN INSTALL"
echo -e  ${WHITE} 
    sudo apt install -y phpmyadmin php-gettext wget
echo -e "${CYAN} PHPMYADMIN INSTALLED ${GREEN}Successfull"
echo -e ""
echo -e ""
echo -e ""
################################################################################
#                                   UTORRENT                                   #
################################################################################

echo -e "${YELLOW} UTORRENT INSTALL"
echo -e ${WHITE}
    sudo apt install -y libssl1.0.0 libssl-dev wget 
    sudo wget http://download-new.utorrent.com/endpoint/utserver/os/linux-x64-ubuntu-13-04/track/beta/ -O utserver.tar.gz 
    sudo tar -zxvf utserver.tar.gz -C /opt/ 
    sudo chmod 777 /opt/utorrent-server-alpha-v3_3/
    sudo ln -s /opt/utorrent-server-alpha-v3_3/utserver /usr/bin/utserver
    sudo wget https://raw.githubusercontent.com/coelhocarlos/debian9-install/master/utorrent
    sudo chmod 755 utorrent
    sudo cp utorrent /etc/init.d/
    cd /etc/init.d/ 
    sudo update-rc.d utorrent defaults
    sudo service utorrent start 
    #systemctl status utorrent.service
    sudo service utorrent restart
    cd /downloads
echo -e "${CYAN} UTORRENT INSTALLED ${GREEN}Successfull"  
echo -e ""
echo -e ""
echo -e ""



################################################################################
#                                   PXE                                        #
################################################################################

echo -e "${YELLOW} PXE INSTALL"
echo -e ${WHITE}
    sudo apt install -y tftpd-hpa wget
    sudo echo 'TFTP_DIRECTORY= "/home/zombie/Servers/Share/tftp"' >> /etc/default/tftpd-hpa
    sudo echo 'RUN_DAEMON="no"' >> /etc/default/tftpd-hpa
    sudo echo 'OPTIONS="-l -s /home/zombie/Servers/Share/tftp"' >> /etc/default/tftpd-hpa
    sudo /etc/init.d/tftpd-hpa restart
    sudo apt install -y isc-dhcp-server wget
    sudo echo "option domain-name "192.168.0.50";" >> /etc/dhcp/dhcpd.conf
    sudo echo "option domain-name-servers 1925.168.0.50, 192.168.0.100;" >> /etc/dhcp/dhcpd.conf
    sudo echo "ddns-update-style interim; authoritative; allow booting; allow bootp; " >> /etc/dhcp/dhcpd.conf
    sudo echo "subnet 192.168.0.0 netmask 255.255.255.0" >>  /etc/dhcp/dhcpd.conf
    sudo echo " {" >> /etc/dhcp/dhcpd.conf
    sudo echo "range 192.168.0.100 192.168.0.254;" >>  /etc/dhcp/dhcpd.conf
    sudo echo "filename "pxelinux.0";" >> /etc/dhcp/dhcpd.conf
    sudo echo "default-lease-time 86400;" >> /etc/dhcp/dhcpd.conf
    sudo echo "max-lease-time 604800;" >> /etc/dhcp/dhcpd.conf
    sudo echo "option subnet-mask 255.255.255.0;"  >> /etc/dhcp/dhcpd.conf
    sudo echo "option broadcast-address 192.168.0.255;" >> /etc/dhcp/dhcpd.conf
    sudo echo "option domain-name-servers 192.168.0.1;" >> /etc/dhcp/dhcpd.conf
    sudo echo "option routers 192.168.0.1;" >>  /etc/dhcp/dhcpd.conf
    sudo echo " }" >>  /etc/dhcp/dhcpd.conf
    #/etc/default/isc-dhcp-server
    
    sudo echo 'INTERFACESv4="enp2s0"' >> /etc/default/isc-dhcp-server
    sudo echo 'INTERFACESv6="enp2s0"' >> /etc/default/isc-dhcp-server
    sudo service isc-dhcp-server restart
    sudo /etc/init.d/tftpd-hpa restart
echo -e "${CYAN} PXE INSTALLED ${GREEN} Successfull" 
echo -e ""
echo -e ""
echo -e ""
################################################################################
#                               KMS SERVER                                     #
################################################################################
    echo -e  "${YELLOW} KMS SERVER INSTALL"
    echo -e  ${WHITE} 
    cd /opt
    sudo git clone https://github.com/myanaloglife/py-kms.git
    sudo echo 'kms:x:501:65534::/nonexistent:/bin/false' >> /etc/passwd
    sudo echo 'kms:*:16342:0:99999:7:::' >> /etc/shadow
    sudo echo '[Unit]' > /etc/systemd/system/py-kms.service
    sudo echo 'Description=Python KMS Server' >> /etc/systemd/system/py-kms.service
    sudo echo >> /etc/systemd/system/py-kms.service
    sudo echo '[Service]' >> /etc/systemd/system/py-kms.service
    sudo echo 'ExecStart=/usr/bin/python /opt/py-kms/server.py' >> /etc/systemd/system/py-kms.service
    sudo echo 'User=kms' >> /etc/systemd/system/py-kms.service
    sudo echo 'Restart=always' >> /etc/systemd/system/py-kms.service
    sudo echo 'RestartSec=1' >> /etc/systemd/system/py-kms.service
    sudo echo >> /etc/systemd/system/py-kms.service
    sudo echo '[Install]' >> /etc/systemd/system/py-kms.service
    sudo echo 'WantedBy=multi-user.target' >> /etc/systemd/system/py-kms.service
    systemctl enable py-kms.service
    systemctl start py-kms.service
   cd
echo -e "${CYAN} KMS SERVER INSTALLED ${GREEN}Successfull" 
echo -e ""
echo -e ""
echo -e ""
################################################################################
#                                  Iptables                                    #
################################################################################
#------------------------
echo  IPTABLES RULES
#------------------------
#-----Allow Established and Related Incoming Connections
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -i enp1s0 -j ACCEPT
iptables -A OUTPUT -o enp1s0 -j ACCEPT
#-----Allow Established Outgoing Connections
iptables -A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
#-----Internal to External
iptables -A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT 
#-----Drop Invalid Packets
#iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
#----Block an IP Address
#iptables -A INPUT -m conntrack --ctstate INVALID -j DROP
#----Block a invalid Packets
#iptables -A INPUT -s 15.15.15.51 -j DROP
#----Reject Network Ip
#iptables -A INPUT -s 15.15.15.51 -j REJECT
#----Reject Network Interfaces
#iptables -A INPUT -i eth0 -s 15.15.15.51 -j DROP

#----Allow Cameras ---
sysctl net.ipv4.ip_forward=1
DEFAULT_FORWARD_POLICY="ACCEPT"
iptables -t nat -A PREROUTING -i enp2s0 -p tcp --dport 9966 -m conntrack --ctstate NEW -j DNAT --to 192.168.0.60:9966
iptables -t nat -A PREROUTING -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT
iptables -A POSTROUTING -t nat -j MASQUERADE
#----Allow All Incoming SSH 
iptables -A INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp -s 15.15.15.0/24 --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#----Allow Outgoing SSH
iptables -A OUTPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#----Allow All Incoming HTTP
iptables -A INPUT -p tcp --dport 80 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 80 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#----Allow All Incoming HTTPS
iptables -A INPUT -p tcp --dport 443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#----Allow All Incoming HTTP and HTTPS
iptables -A INPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp -m multiport --dports 80,443 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#----Allow All Incoming FTP
iptables -A INPUT -p tcp --dport 21-m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 21-m conntrack --ctstate ESTABLISHED -j ACCEPT
#----Allow MySQL from Specific IP Address or Subnet
iptables -A INPUT -p tcp -s 192.168.0.0/24 --dport 3306 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 3306 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#----Allow Email  
iptables -A INPUT -p tcp --dport 25 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 25 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 143 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 143 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#---Allow Eamail SMTP 
iptables -A INPUT -p tcp --dport 143 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 143 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#---Allow Eamail IMAP
iptables -A INPUT -p tcp --dport 993 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 993 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#---Allow All Incoming POP3
iptables -A INPUT -p tcp --dport 110 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 110 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#---Allow All Incoming POP3S
iptables -A INPUT -p tcp --dport 995 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 995 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#---Allow All TEAMSPEAK3
iptables -A INPUT -p tcp --dport 10011 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 10011 -m conntrack --ctstate ESTABLISHED -j ACCEPT

iptables -A INPUT -p tcp --dport 10000 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A INPUT -p tcp --dport 11100 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT


iptables -A INPUT -p tcp --dport 30033 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 30033 -m conntrack --ctstate ESTABLISHED -j ACCEPT
iptables -A INPUT -p udp --dport  9987 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p udp --sport  9987 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#---Allow All MINECRAFT
iptables -A INPUT -p tcp --dport 25565 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
iptables -A OUTPUT -p tcp --sport 25565 -m conntrack --ctstate ESTABLISHED -j ACCEPT
#--Allow All QUAKE
iptables -A INPUT -p udp -m udp --dport 27910:27912 -j ACCEPT
#--Allow All CSTRIKE
iptables -A INPUT -p udp -m udp --dport 27915:27917 -j ACCEPT
#----SAVE
iptables-save > /etc/iptables.up.rules
#----RESTORE
iptables-restore < /etc/iptables.up.rules
#---FLUSH
iptables -F
#---FINISH IPTABLES

################################################################################
#                                  UFW                                         #
################################################################################
echo -e "$YELLOW} UFW SET"
echo -e ${WHITE}
    sudo ufw default deny incoming
    sudo ufw default allow outgoing
    sudo ufw allow 22/tcp
    sudo ufw allow 53
    sudo ufw allow in on enp2s0 to any port 53
    sudo ufw allow 69
    sudo ufw allow in on enp2s0 to any port 69
    sudo ufw allow 80/tcp
    sudo ufw allow in on enp2s0 to any port 80
    sudo ufw allow 443/tcp
    sudo ufw allow in on enp2s0 to any port 443
    sudo ufw allow 2121/tcp
    sudo ufw allow in on enp2s0 to any port 2121
    sudo ufw allow 8080/tcp
    sudo ufw allow in on enp2s0 to any port 8080
    sudo ufw allow 21/tcp
    sudo ufw allow in on enp2s0 to any port 21
    sudo ufw app update plexmediaserver
    sudo ufw allow plexmediaserver-all
    sudo ufw allow apache
    sudo ufw allow webmin
    sudo ufw allow 11000
    sudo ufw allow samba
    sudo ufw allow 32400
    sudo ufw allow 27015
    sudo ufw allow 27018
    sudo ufw allow 25565
    sudo ufw allow 25567
    sudo ufw allow 1688
    sudo ufw allow 61208
    echo -e  ${RED} 
    sudo ufw enable 
    echo -e  ${WHITE}
echo -e ${CYAN}"UFW SET   ${GREEN}ADDED Successful"
echo -e ""
echo -e ""
echo -e ""
################################################################################
#                        PLEX MEDIA SERVER                                     #
################################################################################
 echo -e  "${YELLOW} PLEX MEDIA SERVER INSTALL"
    echo -e  ${WHITE}
    cd downloads/
    sudo curl https://downloads.plex.tv/plex-keys/PlexSign.key | sudo apt-key add -
    sudo echo deb https://downloads.plex.tv/repo/deb public main | sudo tee /etc/apt/sources.list.d/plexmediaserver.list
    sudo apt update
    
    sudo apt install plexmediaserver
    sudo systemctl status plexmediaserver
echo -e "${CYAN} PLEX MEDIA SERVER  INSTALLED ${GREEN}Successfull" 
echo -e ""
echo -e ""
echo -e ""
################################################################################
#                                MINECRAFT                                     #
################################################################################
echo -e "${YELLOW} INSTALL MINECRAFT"
    echo -e  ${WHITE}
sudo apt update
sudo useradd -m -r -d /home/zombie/Server/Games/minecraft minecraft
sudo mkdir /home/zombie/Server/Games/minecraft/survival
sudo wget -O /home/zombie/Server/Games/minecraft/survival/minecraft_server.jar https://s3.amazonaws.com/Minecraft.Download/versions/1.12.2/minecraft_server.1.12.2.jar
sudo bash -c "echo eula=true > /home/zombie/Server/Games/minecraft/survival/eula.txt"
sudo chown -R minecraft /home/zombie/Server/Games/minecraft/survival/

echo "[Unit]" >> /etc/systemd/system/minecraft@.service
echo "Description=Minecraft Server: %i" >> /etc/systemd/system/minecraft@.service
echo "After=network.target" >> /etc/systemd/system/minecraft@.service

echo "[Service]" >> /etc/systemd/system/minecraft@.service
echo "WorkingDirectory= /home/zombie/Server/Games/minecraft/%i" >> /etc/systemd/system/minecraft@.service

echo "User=minecraft" >> /etc/systemd/system/minecraft@.service
echo "Group=minecraft" >> /etc/systemd/system/minecraft@.service
echo "Restart=always" >> /etc/systemd/system/minecraft@.service

#FROM:
#ExecStart=/usr/bin/screen -DmS mc-%i /usr/bin/java -Xmx2G -jar minecraft_server.jar nogui
#TO:
#ExecStart=/usr/bin/screen -DmS mc-%i /usr/bin/java -Xmx4G -jar minecraft_server.jar nogui

echo "ExecStart=/usr/bin/screen -DmS mc-%i /usr/bin/java -Xmx2G -jar minecraft_server.jar nogui" >> /etc/systemd/system/minecraft@.service

echo "ExecStop=/usr/bin/screen -p 0 -S mc-%i -X eval 'stuff "say SERVER SHUTTING DOWN IN 5 SECONDS. SAVING ALL MAPS..."\015'" >> /etc/systemd/system/minecraft@.service
echo "ExecStop=/bin/sleep 5"
echo "ExecStop=/usr/bin/screen -p 0 -S mc-%i -X eval 'stuff "save-all"\015'" >> /etc/systemd/system/minecraft@.service
echo "ExecStop=/usr/bin/screen -p 0 -S mc-%i -X eval 'stuff "stop"\015'" >> /etc/systemd/system/minecraft@.service

echo "[Install]"
echo "WantedBy=multi-user.target"

 #sudo systemctl start minecraft@survival

echo -e {$WRITE}
echo -e "*****************************************************"
echo -e {$WRITE}
echo -e "{$RED} for execute minecraft server use"
echo -e "{$BLUE} sudo systemctl start minecraft@survival"
echo -e "{$RED} for confirm status"
echo -e "{$BLUE} sudo systemctl status minecraft@survival"
echo -e "{$RED} for execute auto start on boot"
echo -e "{$BLUE} sudo systemctl enable minecraft@survival"
echo -e "{$RED} check minecraft port"
echo -e "{$BLUE} nmap -p 25565 localhost"
echo -e {$WRITE}
echo -e "*****************************************************"
echo -e {$WRITE}
#sudo systemctl status minecraft@survival
#sudo systemctl start minecraft@survival
#sudo systemctl status minecraft@survival

echo -e "{$YELLOW}Add server Porperties"
############################### setings minecraft ##########################################
echo -e {$WRITE}
echo "max-tick-time=60000" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "generator-settings=" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "allow-nether=true" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "force-gamemode=false" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "gamemode=0" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "enable-query=false" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "player-idle-timeout=0" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "difficulty=1" >> //home/zombie/games/server/minecraft/survival/server.properties
echo "spawn-monsters=true" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "op-permission-level=4" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "pvp=true" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "snooper-enabled=true" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "level-type=DEFAULT" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "hardcore=false" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "enable-command-block=false" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "max-players=200" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "network-compression-threshold=256" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "resource-pack-sha1=" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "max-world-size=29999984" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "server-port=25565" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "server-ip=" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "spawn-npcs=true" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "allow-flight=false" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "level-name=world" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "view-distance=10" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "resource-pack=" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "spawn-animals=true" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "white-list=false" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "generate-structures=true" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "online-mode=false" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "max-build-height=256" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "level-seed=" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "prevent-proxy-connections=false" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "use-native-transport=true" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "motd=A Minecraft ZOmbie The Zer0 Server" >> /home/zombie/games/server/minecraft/survival/server.properties
echo "enable-rcon=false" >>/home/zombie/games/server/minecraft/survival/server.properties
echo -e "{$YELLOW}Add server Porperties Suscessfull"
echo -e {$WRITE}
echo -e "${CYAN} MINECRAFT INSTALLED ${GREEN}Successfull" 
echo -e ""
echo -e ""
echo -e ""

sudo systemctl stop minecraft@survival
sudo systemctl enable minecraft@survival
sudo systemctl start minecraft@survival
sudo systemctl status minecraft@survival
cd 


################################################################################
#                               FINISH                                         #
################################################################################
echo -e  ${WHITE}
sudo apt-get update && apt-get -y upgrade &&  apt-get -y dist-upgrade
echo -e ${YELLOW}
echo -e  ${WHITE}
echo "shutdown server ?"
echo -e ${YELLOW}
read -r -p "Are you sure? [Y/n]" response
 response=${response,,} # tolower
 if [[ $response =~ ^(yes|y| ) ]] || [[ -z $response ]]; then
    shutdown -r 0
 fi
################################################################################
#                               CHECK PACKAGES                                 #
################################################################################
tput bel
PKG_OK=$(dpkg-query -W --showformat='${Status}\n' plex|grep "install ok installed")
echo -e  Checking for ${BOLD}apache2${WHITE}:  ${GREEN}OK!  "\xE2\x9C\x94" ${WHITE}
if [ "" == "$PKG_OK" ]; then
echo -e  "${RED}apache2 ${YELLOW} Not Installed ${RED}error \u274c\n  ${YELLOW} ${WHITE}"
sudo apt install apache2 wget
fi
declare -a packages=("webmin" "apache2" "php7.2" "plex" "utorrent" "megatools");

for i in "${packages[@]}"; do
    if [ $(dpkg-query -W -f='${Status}' $i 2>/dev/null | grep -c "ok installed") -eq 0 ]; then
        echo -e "$i Not Installed ${RED}error \u274c\n   ${WHITE}";
        echo "$i is not installed, would you like to install it now? (Y/N)";
        read response
        if [ "$response" == "y" ] || [ "$response" == "Y" ]; then
            sudo apt-get install "$i";
        else
            echo "Skipping the installation of $i...";
        fi
    else
        echo -e  "The $i package has already been installed.  ${GREEN} OK! \xE2\x9C\x94  ${WHITE}";
    fi
done

echo -e  "${yellow}checking  packages installed ...${white}"
i=0; n=0; progs=(apache2 mysql phpmyadmin php7.2);
for p in "${progs[@]}"; do
    if hash "$p" &>/dev/null
    then
        echo -e "${green} $p $white} $i is installed ${green} \xE2\x9C\x94 ${wh$
        let c++
    else
        echo -e "${red} $p ${white} $i is not installed ${red} \u274c\n ${white$
        #sudo apt  install  $p wget
        let n++
     fi
 done
printf "%d of %d programs were installed.\n" "$i" "${#progs[@]}"
printf "%d of %d programs were missing\n" "$n" "${#progs[@]}"





