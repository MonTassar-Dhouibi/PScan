#!/usr/bin/python
## Script have two attack [`panel finder || port scanner`]
import socket
import httplib2 
import subprocess
import sys
import time
#import texttable

#from texttable import Texttable
from datetime import datetime

subprocess.call('clear', shell=True)

msg="""\x1b[33m
______  _____                  ___  ___          _____     
| ___ \/  ___|                 |  \/  |         |_   _|    
| |_/ /\ `--.  ___ __ _ _ __   | .  . | ___  _ __ | | __ _ 
|  __/  `--. \/ __/ _` | '_ \  | |\/| |/ _ \| '_ \| |/ _` |
| |    /\__/ / (_| (_| | | | | | |  | | (_) | | | | | (_| |
\_|    \____/ \___\__,_|_| |_| \_|  |_/\___/|_| |_\_/\__,_|
                                                           
_________[+] PScan [+]_[+] V1.01 [+]_[+] By MonTa [+]_______\033[97m"""
print("{:^}".format(msg))
print("\x1b[49m")

msg3="""\033[97m\n PScan  -[ARG] [TARGET SITE] -[ATTACK] --[OPTION]\n\n[+]ARGUMENTS:\n\t-v --victimHost   : give the url adress of the target host\n\n[+]ATTACK:\n\t-a --adminFinder  :select panel finder attack \n\t-p --PortScan     : select Ports Scanner attack\n\n[+]OPTION:\n\t-t --Time_Out     :give the value of timeout in secends\n\t-i --interval     :give the interval of ports begin and end to try \n\nExemple:  PScan -v www.hostname.com -a\n\t  PScan -v www.targetHost.com -p -i 23 84 -t 0.5\n\n\t\033[96m   credit by MonTassar_Dhouibi\n\tuploaded in www.github.com/Monta_0\033[97m"""



l=sys.argv
del l[0]
if len(l)==0:
        print("{}".format(msg3))
        exit()
if l[0]=='-h':
	print("{:=^48}==".format('[*] help [*]'))
	print(msg3)
	exit()
site='';i,time_out,VL,VH=0,0,0,0;a,p=False,False
type='all'
i=0
if l[i]=='-v' and len(l)>1:
	site =l.pop(i+1);del l[i]
else:
	print(msg3)
	exit()
if len(l)==0:
	print('no such attack selected')
	print(msg3)
	exit()
if l[i]=='-p':
	p=True
	del l[i]
	if len(l)!=0:
		while len(l)!=0:
			if  len(l)>2 and l[i]=='-i':
				VL=int(l.pop(i+1));VH=int(l.pop(i+1));del l[i]
			elif len(l)>1 and l[i]=='-t' :
				time_out=float(l.pop(i+1))
				del l[i]
			else:
				print(msg3)
				exit()
elif l[i]=='-a':
	a=True;del l[i]
	if not( len(l)==0):
		if l[i]=='-s' and len(l)>1:
			type=l.pop(i+1)
			type=type.replace("-","")
			del l[i]
		else :
			print("\n\033[91m[!] source code type error -s [SOURCE TYPE]  [!]\033[97m\n")
			print(msg3)
			exit()
else:
	print('no such attack selected')
	print(msg3)
	exit()
                


table=True
try :
	tab = Texttable()
	header = ['Ports']
	tab.header(header)
	tab.set_deco(tab.HEADER |tab.		BORDER)
	tab.set_cols_width([8])
	tab.set_cols_align(["c"])
	tab.set_cols_dtype(['a']) # automatic
except :
	table = False
	input("[\] error with text table press any key to continue without tables")


if 1 == 1 :
    #site = site.replace("http://","")
    print ("\tChecking website " + site + "...")
    h = httplib2.Http()
resp, content = h.request(site)
    if resp.status == 200 : 
        print("\t\033[32m[$] Yes... Server is Online.\033[97m")
        RSIP  = socket.gethostbyname(site)
     else :
         input("\t \033[91m[!] Oops Error occured, Server offline or invalid URL\033[97m")
         exit()





def check(remoteServerIP,t_out,val_L,val_H):
        try:
            t1 = datetime.now()
            varP=""
            L =[]
            for port in range(val_L,val_H+1):
                print("\033[94m[",datetime.now().strftime("%H:%M:%S"),"]","\033[97m[#] cheaking... ",remoteServerIP,":",port)
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(t_out)
                result = sock.connect_ex((remoteServerIP, port))
                if result == 0:
                    print("\n")
                    print("\033[32m[ {} ] [++] {}/{} is Open\033[97m".format(datetime.now().strftime("%H:%M:%S"),port,socket.getservbyport(port)))
                    varP+= str(port)+"/"+socket.getservbyport(port) + "   "
            
                    L.append(str(port)+"/"+socket.getservbyport(port))
                    
                    print("\n")
                    sock.close()
        except KeyboardInterrupt:
        	print("\n\t[!]You pressed Ctrl+C")
        	print("\t[!]Session cancelled...")
        except socket.gaierror:
            print('Hostname could not be resolved. Exiting')
            sys.exit()

        except socket.error:
            print("Couldn't connect to server")
            sys.exit()
        
        
        
        t2 = datetime.now()
        total =  t2 - t1
        
        for k in range(len(L)):
            
            print('{}'.format(L[k]),end="")
            if (k+1) % 2 == 0 :
                print("")
        
        print(varP)
        print('\tScanning Completed in:   {:7.7}'.format(total))




    
if p :
    print("-" * 40)
    print("Scanning remote host\033[95m", RSIP)
    print("\033[97m-" * 40)

    
    if time_out==0:
    	time_out=1
    if VL==0:
    	VL=1
    if VH==0:
    	VH=1025
    check(RSIP,time_out,VL,VH)

var1=0
var2=0
varL=""
if a :

        file=(open("ALL.txt","r")).readlines()
        drag =False
        list=[]
        x =type
        for element in file:
            element=element.replace("\n","")
            if x =="all":
                    if not( element.find("/.end")!=-1 or element.find("++//")!=-1):
                            list.append(element)
            else:
                            if element.find("/.end")!=-1:
                                    drag=False
                            if drag :
                                    list.append(element)
                            if element.find('++//'+x)!=-1:
                                    drag =True
              
              
              
              
        print("\t [+] Scanning " + site + "...\n\n")
        try :
            t1 = datetime.now()
            for admin in list:
                admin = admin.replace("\n","")
                admin = "/" + admin
                host = site + admin
                print ("\t [#] Checking " + host + "...")
                h = httplib2.Http()
                response , content = h.request(host)
             
                var2 = var2 + 1
                if response == 200:
                        var1 = var1 + 1
                        varL+= host +"   "
                        print("%s %s" % ( "\n\n\033[32m[+]\033[97m " + host, "\033[32mAdmin page found!\033[97m"))
                        input("Press enter to continue scanning.\n")
                elif response == 404:
                        var2 = var2
                elif response == 302:
                        print("%s %s" % ("\n>>>" + host, "Possible admin page (302 - Redirect)"))
                else:
                        print("%s %s %s" % (host, " Interesting response:", response.status))
                
            print("\n\nCompleted \n")
            print(var1, " Admin pages found")
            print(var2, " total pages scanned")
            input("[/] Press Enter to Exit")
        except :
            print("\n\t[!] Session Cancelled; Error occured. Check internet settings")
        except (KeyboardInterrupt, SystemExit):
            print("\n\t[!] Session cancelled")


        t2 = datetime.now()
        total =  t2 - t1

        print("\n\033[32m[+] {}\033[97m".format(varL))
        print('\tScanning Completed in:    {:7.7}'.format(total))


