// Aula 11 - Prevenindo ataques de login por força-bruta

/ip firewall filter

add chain=input protocol=tcp dst-port=21 src-address-list=ftp_blacklist action=drop \
comment="Bloqueia ataques de login via FTP"

add chain=output action=accept protocol=tcp content="530 Login incorrect" dst-limit=1/1m,9,dst-address/1m

add chain=output action=add-dst-to-address-list protocol=tcp content="530 Login incorrect" \
address-list=ftp_blacklist address-list-timeout=3


/ip firewall filter

add chain=input protocol=tcp dst-port=22 src-address-list=ssh_blacklist action=drop \
comment="Bloqueia ataques de login via SSH" disabled=no

add chain=input protocol=tcp dst-port=22 connection-state=new \
src-address-list=ssh_stage3 action=add-src-to-address-list address-list=ssh_blacklist \
address-list-timeout=10d comment="" disabled=no

add chain=input protocol=tcp dst-port=22 connection-state=new \
src-address-list=ssh_stage2 action=add-src-to-address-list address-list=ssh_stage3 \
address-list-timeout=1m comment="" disabled=no

add chain=input protocol=tcp dst-port=22 connection-state=new src-address-list=ssh_stage1 \
action=add-src-to-address-list address-list=ssh_stage2 address-list-timeout=1m comment="" disabled=no

add chain=input protocol=tcp dst-port=22 connection-state=new action=add-src-to-address-list \
address-list=ssh_stage1 address-list-timeout=1m comment="" disabled=no


add chain=forward protocol=tcp dst-port=22 src-address-list=ssh_blacklist action=drop \
comment="drop ssh brute downstream" disabled=no

// Aula 17 - Protegendo contra ataques de DoS

ip firewall filter

add chain=forward protocol=tcp connection-state=new tcp-flags=syn jump-target=Protect-SYN action=jump comment="ataque de SYN Flood"

add chain=Protect-SYN protocol=tcp connection-state=new tcp-flags=syn limit=400,5:packet 

add chain=Protect-SYN protocol=tcp connection-state=new tcp-flags=syn action=drop 

ip settings print

Veja se está assim: "tcp-syncookies: no"

ip firewall filter

add chain=forward protocol=icmp action=jump jump-target=PINGOFDEATH comment="Ping da Morte"

add chain=PINGOFDEATH in-interface=ether1 protocol=icmp icmp-options=8:0 limit=1,5:packet action=drop

add chain=PINGOFDEATH protocol=icmp action=drop

 //Aula 16 - Protegendo contra ataques de Brute Force

ip firewall address-list

add address=10.0.0.0 comment=RedeLan list=LIBERADOS

add address=8.8.8.8 comment=DNS1 list=LIBERADOS 
              
add address=208.67.222.222 comment=DNS1 list=LIBERADOS

ip firewall filter

add chain=input in-interface=ether1 protocol=tcp dst-port=22 src-address-list=!LIBERADOS action=add-src-to-address-list log=yes address-list=BRUTE_FORCE address-list-timeout=2h comment="Bloqueio por  Brute Force"

add chain=input in-interface=ether1 protocol=tcp dst-port=80 src-address-list=!LIBERADOS action=add-src-to-address-list log=yes address-list=BRUTE_FORCE address-list-timeout=2h comment="Bloqueio por Brute Force"

add chain=input protocol=tcp dst-port=22 src-address-list=BRUTE_FORCE action=drop log=yes

// Aula 12 - Proteção básica em seu RouterOS

/ip firewall filter
add chain=input connection-state=invalid action=drop \
	comment="Bloqueia conexoes invalidas"  

add chain=input connection-state=established action=accept \
	comment="Permitir conexoes estabelecidas"  
add chain=input protocol=icmp action=accept \
	comment="Permite ICMP" 
add chain=input src-address=192.168.88.0/24 action=accept \
	in-interface=!LAN
add chain=input action=drop comment="Bloqueia todo o resto"

// Aula 13 - Protegendo contra ataques de SynFlood, ICMP Flood, Port Scan, Email Spam, etc.txt


/ip firewall filter


# Criando uma lista de "Syn Flood"
add action=add-src-to-address-list address-list=Syn_Flooder address-list-timeout=30m chain=input \
comment="Adicionar Syn Flood IP a lista" connection-limit=30,32 disabled=no protocol=tcp tcp-flags=syn


# Bloqueando ataques de "SYN flood"
add action=drop chain=input comment="Drop syn flood" disabled=no src-address-list=Syn_Flooder


# Bloqueando ataques de "Port_Scanner", ex: NMAP
add action=add-src-to-address-list address-list=Port_Scanner address-list-timeout=1w chain=input comment="Detectar as ferramentas de Port Scanner"\
disabled=no protocol=tcp psd=21,3s,3,1


# Adicionando na lista de "Port_Scanner"
add action=drop chain=input comment="Drop to port scan list" disabled=no src-address-list=Port_Scanner


# Trabalhando com Jump ICMP ping na cadeia "input"
add action=jump chain=input comment="Jump for icmp input flow" disabled=no jump-target=ICMP protocol=icmp


# Trabalhando com Jump ICMP ping na cadeia "forward"
add action=jump chain=forward comment="Jump for icmp forward flow" disabled=no jump-target=ICMP protocol=icmp


# Bloqueando o acesso do WinBox ao RouterOS, cuidado para criar a lista antes!!
add action=drop chain=input \
comment="Bloquear todo o acesso ao winbox - exceto para a lista de suporte # NAO HABILITAR ESTA REGRA ANTES DE ADICIONAR SUA SUBNET NA LISTA SUPPORTE!!!"\
disabled=yes dst-port=8291 protocol=tcp src-address-list=!supporte

# Bloqueando spams
add action=add-src-to-address-list address-list=spammers address-list-timeout=3h chain=forward comment="Adicione Spammers a lista por 3 horas"\
connection-limit=30,32 disabled=no dst-port=25,587 limit=30/1m,0 protocol=tcp

add action=drop chain=forward comment="Avoid spammers action" disabled=no dst-port=25,587 protocol=tcp src-address-list=spammers


# Aceitando protocolos UDP, TCP e conexões estabilizadas, entre outras na cadeia "INPUT"
add action=accept chain=input comment="Accept DNS - UDP" disabled=no port=53 protocol=udp
add action=accept chain=input comment="Accept DNS - TCP" disabled=no port=53 protocol=tcp
add action=accept chain=input comment="Accept to established connections" connection-state=established disabled=no
add action=accept chain=input comment="Accept to related connections" connection-state=related disabled=no
add action=accept chain=input comment="Acesso total a lista SUPPORTE" disabled=no src-address-list=supporte


# Bloqueia todo o resto na cadeia INPUT, CUIDADO AO USAR!
add action=drop chain=input comment="Bloqueia todo o resto! # NAO HABILITAR ESTA REGRA ANTES DE CERTIFICAR-SE DE LIBERAR AS REGRAS QUE VOCÊ PRECISA"\
disabled=yes


# BLoqueando "Ping Flood"
add action=accept chain=ICMP comment="Echo request - Bloqueando o Ping Flood" disabled=no icmp-options=8:0 limit=1,5 protocol=icmp


# Liberando o "Echo reply", "Time Exceeded", "Destination unreachable" e "Path MTU Discovery"
add action=accept chain=ICMP comment="Echo reply" disabled=no icmp-options=0:0 protocol=icmp
add action=accept chain=ICMP comment="Time Exceeded" disabled=no icmp-options=11:0 protocol=icmp
add action=accept chain=ICMP comment="Destination unreachable" disabled=no icmp-options=3:0-1 protocol=icmp
add action=accept chain=ICMP comment=PMTUD disabled=no icmp-options=3:4 protocol=icmp


# Bloqueia todos os outros ICMP's!
add action=drop chain=ICMP comment="Bloqueia todos os outros ICMP" disabled=no protocol=icmp


# Trabalhando com Jump ICMP ping na cadeia "output"
add action=jump chain=output comment="Jump for icmp output" disabled=no jump-target=ICMP protocol=icmp





























































































































