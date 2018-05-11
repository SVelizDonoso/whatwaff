# WhatWaff
```sh

	
	██╗    ██╗██╗  ██╗ █████╗ ████████╗██╗    ██╗ █████╗ ███████╗███████╗
	██║    ██║██║  ██║██╔══██╗╚══██╔══╝██║    ██║██╔══██╗██╔════╝██╔════╝
	██║ █╗ ██║███████║███████║   ██║   ██║ █╗ ██║███████║█████╗  █████╗  
	██║███╗██║██╔══██║██╔══██║   ██║   ██║███╗██║██╔══██║██╔══╝  ██╔══╝  
	╚███╔███╔╝██║  ██║██║  ██║   ██║   ╚███╔███╔╝██║  ██║██║     ██║     
	 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     
                                                                     
	                        Identificador de Web Application Firewall                                     
    
```
# Descripción
WhatWaff identifica y toma el fingerprints de los productos Web Application Firewall (WAF). 

# Soporte
Por el momento WhatWaff soporta OS Linux

# Dependencias
Antes de ejecutar el script asegúrate de que estén instaladas las dependencias necesarias en tu Linux

```sh
pip install argparse
pip install lxml
pip install urlparse2
pip install requests
pip install BeautifulSoup
pip install builtwith
```

# Instalación
```sh
git clone https://github.com/SVelizDonoso/whatwaff.git
cd whatwaff
python whatwaff.py

	
	██╗    ██╗██╗  ██╗ █████╗ ████████╗██╗    ██╗ █████╗ ███████╗███████╗
	██║    ██║██║  ██║██╔══██╗╚══██╔══╝██║    ██║██╔══██╗██╔════╝██╔════╝
	██║ █╗ ██║███████║███████║   ██║   ██║ █╗ ██║███████║█████╗  █████╗  
	██║███╗██║██╔══██║██╔══██║   ██║   ██║███╗██║██╔══██║██╔══╝  ██╔══╝  
	╚███╔███╔╝██║  ██║██║  ██║   ██║   ╚███╔███╔╝██║  ██║██║     ██║     
	 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     
                                                                     

	    Identificador de Web Application Firewall                                     

                                                           
    Developer :@svelizdonoso                                                      
    GitHub: https://github.com/SVelizDonoso

    
usage: whatwaf.py [-h] [-u URL] [-hs] [-l] [-t] [--version]

optional arguments:
  -h, --help         show this help message and exit
  -u URL, --url URL  URL del Servidor
  -hs, --httpsec     Seguridad cabeceras HTTP
  -l, --list         Waf Soportados por el script
  -t, --tracert      Determinar la ruta que toma un paquete para alcanzar su
                     destino.
  --version          show program's version number and exit

```

# Lista de Waf Soportados

```sh
python whatwaff.py --list


	
	██╗    ██╗██╗  ██╗ █████╗ ████████╗██╗    ██╗ █████╗ ███████╗███████╗
	██║    ██║██║  ██║██╔══██╗╚══██╔══╝██║    ██║██╔══██╗██╔════╝██╔════╝
	██║ █╗ ██║███████║███████║   ██║   ██║ █╗ ██║███████║█████╗  █████╗  
	██║███╗██║██╔══██║██╔══██║   ██║   ██║███╗██║██╔══██║██╔══╝  ██╔══╝  
	╚███╔███╔╝██║  ██║██║  ██║   ██║   ╚███╔███╔╝██║  ██║██║     ██║     
	 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     
                                                                     

	    Identificador de Web Application Firewall                                     

                                                           
    Developer :@svelizdonoso                                                      
    GitHub: https://github.com/SVelizDonoso

    
[*] Lista de WAF Soportados: 
 
[*] Citrix NetScaler
[*] Amazon CloudFront CDN
[*] TrafficShield F5 Networks
[*] ModSecurity
[*] Sucuri WAF
[*] 360
[*] Safedog
[*] NetContinuum
[*] Anquanbao
[*] Baidu Yunjiasu
[*] Knownsec KS-WAF
[*] BIG-IP
[*] Barracuda
[*] BinarySEC
[*] BlockDos
[*] Cisco ACE
[*] CloudFlare
[*] NetScaler
[*] FortiWeb
[*] jiasule
[*] Newdefend
[*] Palo Alto
[*] Safe3WAF
[*] Profense
[*] West263CDN
[*] WebKnight
[*] Wallarm
[*] USP Secure Entry Server
[*] Radware AppWall
[*] PowerCDN
[*] Naxsi
[*] Mission Control Application Shield
[*] IBM WebSphere DataPower
[*] Edgecast
[*] Applicure dotDefender
[*] Comodo WAF
[*] ChinaCache-CDN
[*] NSFocus


```
# Uso de la Herramienta
```sh
python whatwaff.py -u https://www.amazon.com


	
	██╗    ██╗██╗  ██╗ █████╗ ████████╗██╗    ██╗ █████╗ ███████╗███████╗
	██║    ██║██║  ██║██╔══██╗╚══██╔══╝██║    ██║██╔══██╗██╔════╝██╔════╝
	██║ █╗ ██║███████║███████║   ██║   ██║ █╗ ██║███████║█████╗  █████╗  
	██║███╗██║██╔══██║██╔══██║   ██║   ██║███╗██║██╔══██║██╔══╝  ██╔══╝  
	╚███╔███╔╝██║  ██║██║  ██║   ██║   ╚███╔███╔╝██║  ██║██║     ██║     
	 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     
                                                                     

	    Identificador de Web Application Firewall                                     

                                                           
    Developer :@svelizdonoso                                                      
    GitHub: https://github.com/SVelizDonoso

    
[+] Analizando Respuestas de Servidor WAF: https://www.amazon.com
[+] WAF Detectado : Amazon CloudFront CDN


```

```sh

python whatwaff.py -u=https://www.amazont.com --httpsec

	
	██╗    ██╗██╗  ██╗ █████╗ ████████╗██╗    ██╗ █████╗ ███████╗███████╗
	██║    ██║██║  ██║██╔══██╗╚══██╔══╝██║    ██║██╔══██╗██╔════╝██╔════╝
	██║ █╗ ██║███████║███████║   ██║   ██║ █╗ ██║███████║█████╗  █████╗  
	██║███╗██║██╔══██║██╔══██║   ██║   ██║███╗██║██╔══██║██╔══╝  ██╔══╝  
	╚███╔███╔╝██║  ██║██║  ██║   ██║   ╚███╔███╔╝██║  ██║██║     ██║     
	 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     
                                                                     

	    Identificador de Web Application Firewall                                     

                                                           
    Developer :@svelizdonoso                                                      
    GitHub: https://github.com/SVelizDonoso

    
[+] Auditoria Seguridad Header HTTP : https://www.amazon.com

[*] x-xss-protection  ....[FAIL]
[*] x-content-type-options  ....[FAIL]
[*] content-security-policy  ....[FAIL]
[*] x-powered-by  Cabecera Eliminada ......[OK]
[*] x-frame-options  Valor:SAMEORIGIN .....[OK]
[*] strict-transport-security  Valor:max-age=47474747; includeSubDomains; preload .....[OK]
[*] access-control-allow-origin  Cabecera Eliminada ......[OK]
[*] server  Valor:Server ....[WARM]
[*] Soporte de HTTPS  ...............[OK]
[*] Certificado HTTPS ...............[OK]
[*] Redireccion HTTP -> HTTPS .......[OK]


[+] Analizando Respuestas de Servidor WAF: https://www.amazon.com
[+] WAF Detectado : Amazon CloudFront CDN


```

```sh
python whatwaf.py -u https://www.amazon.com --httpsec --tracert


	
	██╗    ██╗██╗  ██╗ █████╗ ████████╗██╗    ██╗ █████╗ ███████╗███████╗
	██║    ██║██║  ██║██╔══██╗╚══██╔══╝██║    ██║██╔══██╗██╔════╝██╔════╝
	██║ █╗ ██║███████║███████║   ██║   ██║ █╗ ██║███████║█████╗  █████╗  
	██║███╗██║██╔══██║██╔══██║   ██║   ██║███╗██║██╔══██║██╔══╝  ██╔══╝  
	╚███╔███╔╝██║  ██║██║  ██║   ██║   ╚███╔███╔╝██║  ██║██║     ██║     
	 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     
                                                                     

	    Identificador de Web Application Firewall                                     

                                                           
    Developer :@svelizdonoso                                                      
    GitHub: https://github.com/SVelizDonoso

    
[+] DNS: www.amazon.com
[+] IP : 104.104.162.220

[*] Verificando Ruta del Servidor :
[-] 1	192.168.1.1
[-] 2	10.50.1.113
[-] 3	10.50.1.26
[-] 4	5.53.1.89
[-] 5	84.16.12.39
[-] 6	176.52.254.157
[-] 7	94.142.97.221
[-] 8	94.142.98.95
[-] 9	187.100.197.62
[-] 10	189.108.16.66
[-] 11	189.108.16.66
[-] 12	186.202.44.85
[-] 13	200.160.195.161
[-] 14	177.190.108.29
[-] 15	186.192.128.46
[-] 16	186.192.128.46
[-] 17	104.104.162.220

[+] Auditoria Seguridad Header HTTP : https://www.amazon.com

[*] x-xss-protection  ....[FAIL]
[*] x-content-type-options  ....[FAIL]
[*] content-security-policy  ....[FAIL]
[*] x-powered-by  Cabecera Eliminada ......[OK]
[*] x-frame-options  Valor:SAMEORIGIN .....[OK]
[*] strict-transport-security  Valor:max-age=47474747; includeSubDomains; preload .....[OK]
[*] access-control-allow-origin  Cabecera Eliminada ......[OK]
[*] server  Valor:Server ....[WARM]
[*] Soporte de HTTPS  ...............[OK]
[*] Certificado HTTPS ...............[OK]
[*] Redireccion HTTP -> HTTPS .......[OK]


[+] Analizando Respuestas de Servidor WAF: https://www.amazon.com
[+] WAF Detectado : Amazon CloudFront CDN

```

# Advertencia
Este software se creo SOLAMENTE para fines educativos. No soy responsable de su uso. Úselo con extrema precaución.

# Autor
@sveliz https://github.com/SVelizDonoso/
