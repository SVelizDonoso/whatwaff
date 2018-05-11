#!/usr/bin/env python
# -*- coding:utf-8 -*-

# WHATWAFF es creado para reconocimiento de objetivos WEB
# este escript deberia ser usado antes de cualquier escaneo de vulnerabilidades a un sitio web
# Creacion 2018
# autor: @svelizdonoso
# git: https://github.com/SVelizDonoso


from copy import deepcopy
from urlparse import urljoin
from lxml.html import etree
import re
import os
import requests
import optparse
import sys
import urllib2
import random
import httplib
import socket 
import ssl
import argparse
from urlparse import urlparse
from optparse import OptionParser

cwd, filename=  os.path.split(os.path.abspath(__file__))

class SecurityHeaders():
    def __init__(self):
        pass

    def evaluate_warn(self, header, contents):

        warn = 1

        if header == 'x-frame-options':
            if contents.lower() in ['deny', 'sameorigin']:
                warn = 0
            else:
                warn = 1
    
        if header == 'strict-transport-security':
            warn = 0

        if header == 'content-security-policy':
            warn = 0

        if header == 'access-control-allow-origin':
            if contents == '*':
                warn = 1
            else:
                warn = 0
    
        if header == 'x-xss-protection':
            if contents.lower() in ['1', '1; mode=block']:
                warn = 0
            else:
                warn = 1

        if header == 'x-content-type-options':
            if contents.lower() == 'nosniff':
                warn = 0
            else:
                warn =1

        if header == 'x-powered-by' or header == 'server':
            if len(contents) > 1:
                warn = 1
            else: 
                warn = 0

        return {'defined': True, 'warn': warn, 'contents': contents}

    def test_https(self, url):
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        sslerror = False
            
        conn = httplib.HTTPSConnection(hostname)
        try:
            conn.request('GET', '/')
            res = conn.getresponse()
        except socket.gaierror:
            return {'supported': False, 'certvalid': False}
        except ssl.CertificateError:
            return {'supported': True, 'certvalid': False}
        except:
            sslerror = True

        if sslerror:
            conn = httplib.HTTPSConnection(hostname, timeout=5, context = ssl._create_unverified_context() )
            try:
                conn.request('GET', '/')
                res = conn.getresponse()
                return {'supported': True, 'certvalid': False}
            except:
                return {'supported': False, 'certvalid': False}

        return {'supported': True, 'certvalid': True}

    def test_http_to_https(self, url, follow_redirects = 5):
        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if not protocol:
            protocol = 'http' 

        if protocol == 'https' and follow_redirects != 5:
            return True
        elif protocol == 'https' and follow_redirects == 5:
            protocol = 'http'

        if (protocol == 'http'):
            conn = httplib.HTTPConnection(hostname)
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
        except socket.gaierror:
            print '[*] Fallo la Solicitud HTTP '
            return False

       
        if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
            for header in headers:
                if (header[0] == 'location'):
                    return self.test_http_to_https(header[1], follow_redirects - 1) 

        return False

    def check_headers(self, url, follow_redirects = 0):
      
        retval = {
            'x-frame-options': {'defined': False, 'warn': 1, 'contents': '' },
            'strict-transport-security': {'defined': False, 'warn': 1, 'contents': ''},
            'access-control-allow-origin': {'defined': False, 'warn': 0, 'contents': ''},
            'content-security-policy': {'defined': False, 'warn': 1, 'contents': ''},
            'x-xss-protection': {'defined': False, 'warn': 1, 'contents': ''}, 
            'x-content-type-options': {'defined': False, 'warn': 1, 'contents': ''},
            'x-powered-by': {'defined': False, 'warn': 0, 'contents': ''},
            'server': {'defined': False, 'warn': 0, 'contents': ''} 
        }

        parsed = urlparse(url)
        protocol = parsed[0]
        hostname = parsed[1]
        path = parsed[2]
        if (protocol == 'http'):
            conn = httplib.HTTPConnection(hostname)
        elif (protocol == 'https'):
               
                conn = httplib.HTTPSConnection(hostname, context = ssl._create_unverified_context() )
        else:
            
            return {}
    
        try:
            conn.request('HEAD', path)
            res = conn.getresponse()
            headers = res.getheaders()
        except socket.gaierror:
            print '[*] Fallo la Solicitud HTTP '
            return False

        if (res.status >= 300 and res.status < 400  and follow_redirects > 0):
            for header in headers:
                if (header[0] == 'location'):
                    return self.check_headers(header[1], follow_redirects - 1) 
                
        
        for header in headers:
            if (header[0] in retval):
                retval[header[0]] = self.evaluate_warn(header[0], header[1])

        return retval

LISTA_WAF = [
    '[*] Citrix NetScaler',
    '[*] Amazon CloudFront CDN',
    '[*] TrafficShield F5 Networks',
    '[*] ModSecurity',
    '[*] Sucuri WAF',
    '[*] 360',
    '[*] Safedog',
    '[*] NetContinuum',
    '[*] Anquanbao',
    '[*] Baidu Yunjiasu',
    '[*] Knownsec KS-WAF',
    '[*] BIG-IP',
    '[*] Barracuda',
    '[*] BinarySEC',
    '[*] BlockDos',
    '[*] Cisco ACE',
    '[*] CloudFlare',
    '[*] NetScaler',
    '[*] FortiWeb',
    '[*] jiasule',
    '[*] Newdefend',
    '[*] Palo Alto',
    '[*] Safe3WAF',
    '[*] Profense',
    '[*] West263CDN',
    '[*] WebKnight',
    '[*] Wallarm',
    '[*] USP Secure Entry Server',
    '[*] Radware AppWall',
    '[*] PowerCDN',
    '[*] Naxsi',
    '[*] Mission Control Application Shield',
    '[*] IBM WebSphere DataPower',
    '[*] Edgecast',
    '[*] Applicure dotDefender',
    '[*] Comodo WAF',
    '[*] ChinaCache-CDN',
    '[*] NSFocus'
]

WAF_PAYLOAD = (
                        "",
                        "search=<script>alert(1)</script>",
                        "file=../../../../../../etc/passwd",
                        "id=1 AND 1=1 UNION ALL SELECT 1,2,3,table_name FROM information_schema.tables WHERE 2>1--"
                     )


def banner():
    print """

	
	██╗    ██╗██╗  ██╗ █████╗ ████████╗██╗    ██╗ █████╗ ███████╗███████╗
	██║    ██║██║  ██║██╔══██╗╚══██╔══╝██║    ██║██╔══██╗██╔════╝██╔════╝
	██║ █╗ ██║███████║███████║   ██║   ██║ █╗ ██║███████║█████╗  █████╗  
	██║███╗██║██╔══██║██╔══██║   ██║   ██║███╗██║██╔══██║██╔══╝  ██╔══╝  
	╚███╔███╔╝██║  ██║██║  ██║   ██║   ╚███╔███╔╝██║  ██║██║     ██║     
	 ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝     ╚═╝     
                                                                     

	    Identificador de Web Application Firewall                                     

                                                           
    Developer :@svelizdonoso                                                      
    GitHub: https://github.com/SVelizDonoso

    """

def listWaf():
	print "[*] Lista de WAF Soportados: "
        print " "
	for waf in LISTA_WAF:
		print waf

def help():
    # Menu de opciones del script
	parser = optparse.OptionParser('Uso: python %prog [options]( Ejemplo: python %prog -u http://www.sitioprueba.com/)')
	parser.add_argument('-u','--url', action='store', dest='url',help='URL del Servidor')
	parser.add_argument('--headsec', action='store', dest='hsec',help='Listar Seguridad Cabeceras HTTP')
	parser.add_argument('--version', action='version', version='%(prog)s 1.0')
        return parser.parse_args()

class bcolors:
    HEADER = '\033[95m'
    OKBLUE = '\033[94m'
    OKGREEN = '\033[92m'
    WARNING = '\033[93m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'	

def Browsers():
	  br = [
                "Mozilla/5.0 (X11; U; Linux x86_64; en-US; rv:1.9.1.3) Gecko/20090913 Firefox/3.5.3",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
		"Mozilla/5.0 (Windows; U; Windows NT 5.2; en-US; rv:1.9.1.3) Gecko/20090824 Firefox/3.5.3 (.NET CLR 3.5.30729)",
		"Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.1) Gecko/20090718 Firefox/3.5.1",
		"Mozilla/5.0 (Windows; U; Windows NT 5.1; en-US) AppleWebKit/532.1 (KHTML, like Gecko) Chrome/4.0.219.6 Safari/532.1",
		"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.1; WOW64; Trident/4.0; SLCC2; .NET CLR 2.0.50727; InfoPath.2)",
		"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 6.0; Trident/4.0; SLCC1; .NET CLR 2.0.50727; .NET CLR 1.1.4322; .NET CLR 3.5.30729; .NET CLR 3.0.30729)",
		"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.2; Win64; x64; Trident/4.0)",
		"Mozilla/4.0 (compatible; MSIE 8.0; Windows NT 5.1; Trident/4.0; SV1; .NET CLR 2.0.50727; InfoPath.2)Mozilla/5.0 (Windows; U; MSIE 7.0; Windows NT 6.0; en-US)",
		"Mozilla/4.0 (compatible; MSIE 6.1; Windows XP)"
		]
	  user_agent = {'User-agent': random.choice(br) }
	  return user_agent
   


class whatwaf(object):
    def __init__(self,url):

        self._finger = ''
        self._nowaf = ''
        self._url = url
    def _run(self):
        try:
            self.scan_site()
        except:
            print "[+] Sitio Web a Auditar : " +self._url
            raise


    def scan_site(self):
        print "[+] Analizando Respuestas de Servidor WAF: " +self._url
	acum = 0
	for payload in WAF_PAYLOAD:
            turl= ''
            turl = deepcopy(self._url)
            add_url = payload
            turl = urljoin(turl, add_url)

	    try:
                resp = requests.get(turl,headers = Browsers() ,allow_redirects=False)
	    except:
		 print "[+] Error al acceder al Servidor : " +self._url

            det = self.check_waf(resp)
	    if det > 0 :
		acum +=1
	if acum < 1 :
		print bcolors.OKGREEN + "[*] No se Detecto WAF en la Auditoria." + bcolors.ENDC
		print ""
	else:
	        print bcolors.WARNING + "[+] WAF Detectado : " + self._finger + bcolors.ENDC
                print ""
            

    def check_waf(self, resp):
        self._xmlstr_dom = etree.parse(cwd+'/fingerprinting.xml')
        waf_doms = self._xmlstr_dom.xpath("waf")
        detect = 0 
        for waf_dom in waf_doms:
            finger_dom = waf_dom.xpath("finger")
            rule_dom = finger_dom[0].xpath("rule")
            head_type =rule_dom[0].get("header").lower()
            if head_type in resp.headers:
                 regx = self.regexp_header(rule_dom,waf_dom,head_type,resp)
		 if regx > 0 :
			detect +=1
	return detect
		
           

    def regexp_header(self,rule_dom,waf_dom,head_type,resp):
            regmatch_dom = rule_dom[0].xpath("regmatch")
            regexp_doms = regmatch_dom[0].xpath("regexp") if regmatch_dom != None else []
            regexp = 0
            for regexp_dom in regexp_doms:
                exp_pattern = re.compile(regexp_dom.text)

                if exp_pattern.search(resp.headers[head_type]):
                   self._finger=waf_dom.get("name")
                   regexp += 1
            return regexp
                    
    
def initSecHttp(url,redirects=3):
	foo = SecurityHeaders()
	parsed = urlparse(url)
        print "[+] Auditoria Seguridad Header HTTP : " +str(url)
	print ""
	if not parsed.scheme:
        	url = 'http://' + url 
	headers = foo.check_headers(url, redirects)
	if not headers:
        	sys.exit(1)
	for header, value in headers.iteritems():
        	if value['warn'] == 1:
            		if value['defined'] == False:
                		print bcolors.FAIL+'[*] ' + header + '  ....[FAIL]'+bcolors.ENDC
            		else:
                		print bcolors.WARNING+'[*] ' + header + '  Valor:' + value['contents'] + ' ....[WARM]'+bcolors.ENDC
        	elif value['warn'] == 0:
            		if value['defined'] == False:
                		print bcolors.OKGREEN + '[*] ' + header + '  Cabecera Eliminada ......[OK]'+bcolors.ENDC
            		else:
                		print bcolors.OKGREEN + '[*] ' + header + '  Valor:' + value['contents'] + ' .....[OK]'+bcolors.ENDC

	https = foo.test_https(url)
    	if https['supported']:
        	print bcolors.OKGREEN + '[*] Soporte de HTTPS  ...............[OK]'+bcolors.ENDC
    	else:
        	print bcolors.FAIL+'[*] Soporte de HTTPS  ....................[FAIL]'+bcolors.ENDC

	if https['certvalid']:
        	print bcolors.OKGREEN + '[*] Certificado HTTPS ...............[OK]'+bcolors.ENDC
    	else:
        	print bcolors.FAIL+'[*] Certificado HTTPS ....................[FAIL]'+bcolors.ENDC


    	if foo.test_http_to_https(url, 5):
        	print bcolors.OKGREEN + '[*] Redireccion HTTP -> HTTPS .......[OK]'+bcolors.ENDC
    	else:
        	print bcolors.FAIL+'[*] Redireccion HTTP -> HTTPS  ...........[FAIL]'+bcolors.ENDC
	print "\n"


def traceroute(dest_addr, max_hops=30, timeout=0.2):
    print "[*] Verificando Ruta del Servidor :"
    proto_icmp = socket.getprotobyname('icmp')
    proto_udp = socket.getprotobyname('udp')
    port = 33434

    for ttl in xrange(1, max_hops+1):
        rx = socket.socket(socket.AF_INET, socket.SOCK_RAW, proto_icmp)
        rx.settimeout(timeout)
        rx.bind(('', port))
        tx = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, proto_udp)
        tx.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
        tx.sendto('', (dest_addr, port))

        try:
            data, curr_addr = rx.recvfrom(512)
            curr_addr = curr_addr[0]
        except socket.error:
            curr_addr = None
        finally:
            rx.close()
            tx.close()

        yield curr_addr

        if curr_addr == dest_addr:
            break
def quitURL(dest_name):
	sitio =dest_name.replace("http://", "")
	sitio = sitio.replace("https://", "")
	sitio = sitio.replace("/", "")
        return sitio

def help():
    # Menu que se despliega solamente si al script se le pasan argumentos
	parser = argparse.ArgumentParser()
	parser.add_argument('-u','--url', action='store', dest='url',help='URL del Servidor')
	parser.add_argument('-hs','--httpsec', action='store_true', dest='hsec',help='Seguridad cabeceras HTTP')
	parser.add_argument('-l', '--list',action='store_true', dest='list',help='Waf Soportados por el script')
        parser.add_argument('-t', '--tracert',action='store_true', dest='tracert',help='Determinar la ruta que toma un paquete para alcanzar su destino. ')
	parser.add_argument('--version', action='version', version='%(prog)s 1.0')
        return parser


if __name__ == '__main__':
    banner()
    results = help()
    res = results.parse_args()

    if res.list == True:
        listWaf()
	print "\n\n"
        sys.exit()
    if res.tracert== True :
	dest_name = str(quitURL(res.url))
    	dest_addr = socket.gethostbyname(dest_name)
    	print "[+] DNS: " + dest_name
	print "[+] IP : "+ dest_addr
	print ""
    	for i, v in enumerate(traceroute(dest_addr)):
        	print "[-] %d\t%s" % (i+1, v)
	print ""
    if res.hsec == True :
	initSecHttp(res.url)
	wafidentify = whatwaf(res.url)
        wafidentify._run()
	sys.exit()
    if res.url == None or res.url == "":
        results.print_help()
        sys.exit()
    else:
       wafidentify = whatwaf(res.url)
       wafidentify._run()
       sys.exit()

