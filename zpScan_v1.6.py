#!/usr/bin/python3

import nmap

from tabulate import tabulate

import re

import json

import requests

import os.path

from os.path import exists as file_exists

import time

#gets todays date and local time for filenames
seconds=time.time()
localtime=time.ctime(seconds)
dategetter=localtime.split(' ')
date_for_filename=dategetter[1]+'_'+dategetter[2]+'_'+dategetter[4]

zpScan = nmap.PortScanner()

ipv4_subnet_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}(?:/\d{1,2}|)$")
ipv4_regex = re.compile(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$")

zpScan_art="""                                                                                                                
                                                                                                                
                                        SSSSSSSSSSSSSSS                                                         
                                      SS:::::::::::::::S                                                        
                                     S:::::SSSSSS::::::S                                                                 
                                     S:::::S     SSSSSSS                                                        
zzzzzzzzzzzzzzzzzppppp   ppppppppp   S:::::S                cccccccccccccccc  aaaaaaaaaaaaa   nnnn  nnnnnnnn    
z:::::::::::::::zp::::ppp:::::::::p  S:::::S              cc:::::::::::::::c  a::::::::::::a  n:::nn::::::::nn  
z::::::::::::::z p:::::::::::::::::p  S::::SSSS          c:::::::::::::::::c  aaaaaaaaa:::::a n::::::::::::::nn 
zzzzzzzz::::::z  pp::::::ppppp::::::p  SS::::::SSSSS    c:::::::cccccc:::::c           a::::a nn:::::::::::::::n
      z::::::z    p:::::p     p:::::p    SSS::::::::SS  c::::::c     ccccccc    aaaaaaa:::::a   n:::::nnnn:::::n
     z::::::z     p:::::p     p:::::p       SSSSSS::::S c:::::c               aa::::::::::::a   n::::n    n::::n
    z::::::z      p:::::p     p:::::p            S:::::Sc:::::c              a::::aaaa::::::a   n::::n    n::::n
   z::::::z       p:::::p    p::::::p            S:::::Sc::::::c     ccccccca::::a    a:::::a   n::::n    n::::n
  z::::::zzzzzzzz p:::::ppppp:::::::pSSSSSSS     S:::::Sc:::::::cccccc:::::ca::::a    a:::::a   n::::n    n::::n
 z::::::::::::::z p::::::::::::::::p S::::::SSSSSS:::::S c:::::::::::::::::ca:::::aaaa::::::a   n::::n    n::::n
z:::::::::::::::z p::::::::::::::pp  S:::::::::::::::SS   cc:::::::::::::::c a::::::::::aa:::a  n::::n    n::::n
zzzzzzzzzzzzzzzzz p::::::pppppppp     SSSSSSSSSSSSSSS       cccccccccccccccc  aaaaaaaaaa  aaaa  nnnnnn    nnnnnn
                  p:::::p                                                                                       
                  p:::::p        Welcome to zpScan, an interactive Python script using the nmap library; made for        
                 p:::::::p       simplifying scanning & enumeration, and outputting your results in table format.       
                 p:::::::p                                                                                  
                 p:::::::p                                                                           Version: 1.6        
                 ppppppppp                Written by Zachary Harvey & Pamela Tobon | Powered by Fullstack Academy                                                                                 
                                                                                                                """
print(zpScan_art)                                                                           
bigline='<~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~>'
print(bigline)

def top_scan():
    scan_choice=''
    scan_numb = input("""
        Please enter the type of scan you want to run or enter 7 to exit zpScan:\n
            1) Ping Scan
            2) Fast Scan
            3) Top Ports Scan
            4) UDP Scan
            5) Comprehensive Scan                (Requires terminal to be full screen)
            6) Lite CPE/CVE Vulnerability Scan   (Requires terminal to be full screen & host connection to internet)
            
            7) Exit zpScan
                        \nChoose your scan number --> """)
    print("You have selected option: ", scan_numb)
    print(bigline)
    if scan_numb == '1':
        scan_choice='pingscan'
        while True:
            ip_addr1 = input("Please enter the target IP or Network (IP/CIDR) you would like to Ping scan:\nExample: 192.168.56.108 or 192.168.56.0/24\nIP or IP/CIDR --> ")
            if ipv4_subnet_regex.search(ip_addr1):
                print("The IP address entered is valid: ", ip_addr1)
                break

        version=zpScan.nmap_version()
        print(bigline)
        print("Nmap Version:   "+str(version[0])+'.'+str(version[1]))
        print('Please wait while your scan is completed. It may take some time.')
        print(bigline)
        zpScan.scan(hosts=ip_addr1, arguments='-sn')
        
        option_1_list = []
        for ip in zpScan.all_hosts():
            ip_addr1 = ip
            if 'mac' in zpScan[ip_addr1]['addresses']:
                mac = zpScan[ip_addr1]['addresses']['mac']
            else:
                mac = ''
            var = (zpScan[ip_addr1]['addresses']['ipv4'], mac, zpScan[ip_addr1]['status']['state'])
            option_1_list.append(var)
        columns = ["Host", "MAC Address", "Status"]
        print(tabulate(option_1_list, headers=columns, tablefmt="fancy_grid"))

    if scan_numb == '2':
        scan_choice='fastscan'
        while True:
            ip_addr2 = input("Please enter the target IP or Network (IP/CIDR) you would like to Fast scan:\nExample: 192.168.56.108 or 192.168.56.0/24\nIP or IP/CIDR --> ")
            if ipv4_subnet_regex.search(ip_addr2):
                print("The IP address entered is valid: ", ip_addr2)
                break

        version=zpScan.nmap_version()
        print(bigline)
        print("Nmap Version:   "+str(version[0])+'.'+str(version[1]))
        print('Please wait while your scan is completed. It may take some time.')
        zpScan.scan(hosts=ip_addr2, arguments='-F')
        print(bigline)
        for ip in zpScan.all_hosts():
            ip_addr2=ip
            if zpScan[ip_addr2].state()=='up':
                print("Host: ", zpScan[ip_addr2]['addresses']['ipv4'])
                if 'mac' in zpScan[ip_addr2]['addresses']:
                    if zpScan[ip_addr2]['vendor']!={}:
                        vendor = zpScan[ip_addr2]['vendor'][zpScan[ip_addr2]['addresses']['mac']]
                        print('MAC Address: '+ zpScan[ip_addr2]['addresses']['mac'] + ' (' + vendor + ')')
                    else: 
                        print('MAC Address: ', zpScan[ip_addr2]['addresses']['mac'])

                print("Host Status: ", zpScan[ip_addr2].state())
            if 'tcp' in zpScan[ip_addr2]:
                proto = zpScan[ip_addr2].all_protocols()
                print('Protocol: '+ str(proto[0]))
                ports = zpScan[ip_addr2]['tcp'].keys()           
                option_5_list = []
                for port in ports:
                    print_statement = (port, zpScan[ip_addr2]['tcp'][port]['state'], zpScan[ip_addr2]['tcp'][port]['name'])
                    option_5_list.append(print_statement)
                columns = ['Port', 'State', 'Service']
                print(tabulate(option_5_list, headers = columns, tablefmt="fancy_grid"))
            if 'tcp' not in zpScan[ip_addr2]:
                print('There does not appear to be any open TCP ports for this host')
            print(bigline)

    if scan_numb == '3':
        scan_choice='top_ports_scan'
        while True:
            ip_addr3 = input("Please enter the target IP or Network (IP/CIDR) you would like to scan for Top Ports:\nExample: 192.168.56.108 or 192.168.56.0/24\nIP or IP/CIDR --> ")
            if ipv4_subnet_regex.search(ip_addr3):
                print("The IP address entered is valid: ", ip_addr3)
                break

        port_count = input("please specify the number of top ports you would like to scan: ")

        version=zpScan.nmap_version()
        print(bigline)
        print("Nmap Version:   "+str(version[0])+'.'+str(version[1]))
        print('Please wait while your scan is completed. It may take some time.')
        zpScan.scan(hosts=ip_addr3, arguments='--top-ports {0}'.format(port_count))
        print(bigline)
        for ip in zpScan.all_hosts():
            ip_addr3=ip   
            if zpScan[ip_addr3].state()=='up':
                print("Host: ", zpScan[ip_addr3]['addresses']['ipv4'])
                if 'mac' in zpScan[ip_addr3]['addresses']:
                    if zpScan[ip_addr3]['vendor']!={}:
                        vendor = zpScan[ip_addr3]['vendor'][zpScan[ip_addr3]['addresses']['mac']]
                        print('MAC Address: '+ zpScan[ip_addr3]['addresses']['mac'] + ' (' + vendor + ')')
                    else: 
                        print('MAC Address: ', zpScan[ip_addr3]['addresses']['mac'])

                print("Host Status: ", zpScan[ip_addr3].state())
            if 'tcp' in zpScan[ip_addr3]:
                proto = zpScan[ip_addr3].all_protocols()
                print('Protocol: '+ str(proto[0]))
                ports = zpScan[ip_addr3]['tcp'].keys()
                option_3_list = []
                for port in ports:
                    print_statement = ((port, zpScan[ip_addr3]['tcp'][port]['state'], zpScan[ip_addr3]['tcp'][port]['reason'], zpScan[ip_addr3]['tcp'][port]['name']))
                    option_3_list.append(print_statement)
                columns = ['Port', 'State', 'Reason', 'Service']
                print(tabulate(option_3_list, headers = columns, tablefmt="fancy_grid"))
            if 'tcp' not in zpScan[ip_addr3]:
                print('There does not appear to be any open TCP ports for this host')
            print(bigline)

    if scan_numb == '4':
        scan_choice="udpscan"
        while True:
            ip_addr4 = input("Please enter the target IP or Network (IP/CIDR) you would like to UDP scan:\nExample: 192.168.56.108 or 192.168.56.0/24\nIP or IP/CIDR --> ")
            if ipv4_subnet_regex.search(ip_addr4):
                print("The IP address entered is valid: ", ip_addr4)
                break

        version=zpScan.nmap_version()
        print(bigline)
        print("Nmap Version:   "+str(version[0])+'.'+str(version[1]))
        print('Please wait while your scan is completed. It may take some time.')
        zpScan.scan(hosts=ip_addr4, arguments='-sUV -F')
        print(bigline)
        for ip in zpScan.all_hosts():
            ip_addr4=ip
            if zpScan[ip_addr4].state()=='up':
                print("Host: ", zpScan[ip_addr4]['addresses']['ipv4'])
                if 'mac' in zpScan[ip_addr4]['addresses']:
                    if zpScan[ip_addr4]['vendor']!={}:
                        vendor = zpScan[ip_addr4]['vendor'][zpScan[ip_addr4]['addresses']['mac']]
                        print('MAC Address: '+ zpScan[ip_addr4]['addresses']['mac'] + ' (' + vendor + ')')
                    else: 
                        print('MAC Address: ', zpScan[ip_addr4]['addresses']['mac'])

                print("Host Status: ", zpScan[ip_addr4].state())
            if 'udp' in zpScan[ip_addr4]:
                proto = zpScan[ip_addr4].all_protocols()
                print('Protocol: '+ str(proto[0]))
                ports = zpScan[ip_addr4]['udp'].keys()           
                option_4_list = []
                for port in ports:
                    print_statement_2 = (port, zpScan[ip_addr4]['udp'][port]['state'], zpScan[ip_addr4]['udp'][port]['reason'], zpScan[ip_addr4]['udp'][port]['name'], zpScan[ip_addr4]['udp'][port]['product'], zpScan[ip_addr4]['udp'][port]['version'])
                    option_4_list.append(print_statement_2)
                columns = ['Port', 'State', 'Reason', 'Service', 'Product', 'Version' ]
                print(tabulate(option_4_list, headers = columns, tablefmt="fancy_grid"))
            if 'udp' not in zpScan[ip_addr4]:
                print('There does not appear to be any open UDP ports for this host')
            print(bigline) 

    if scan_numb=='5':
        scan_choice='comprehensive_scan'
        while True:
            ip_addr5 = input("Please enter the target IP or Network (IP/CIDR) you would like to Comprehensive scan:\nExample: 192.168.56.108 or 192.168.56.0/24\nIP or IP/CIDR --> ")
            if ipv4_subnet_regex.search(ip_addr5):
                print("The IP address entered is valid: ", ip_addr5)
                break

        version=zpScan.nmap_version()                                                  
        print(bigline)
        print("Nmap Version:   "+str(version[0])+'.'+str(version[1]))
        print('Please wait while your scan is completed. It may take some time.')
        zpScan.scan(hosts=ip_addr5, arguments='-v -sS -sV -sC -A -O')
        print(bigline)
        for ip in zpScan.all_hosts():
            ip_addr=ip
            if zpScan[ip_addr].state()=='up':
                print('Here is your full report for Host:'+ip_addr+'\n')
                if 'mac' in zpScan[ip_addr]['addresses']:
                    if zpScan[ip_addr]['addresses']['mac']!='':
                        if zpScan[ip_addr]['vendor']!={}:
                            print('Mac address:'+zpScan[ip_addr]['addresses']['mac']+' ('+zpScan[ip_addr]['vendor'][zpScan[ip_addr]['addresses']['mac']]+')'+'\n')
                        else:
                            print('Mac address:'+zpScan[ip_addr]['addresses']['mac']+'\n')
                if 'osmatch' in zpScan[ip_addr]:
                    if zpScan[ip_addr]['osmatch']!=[]:   
                        if 'accuracy' in zpScan[ip_addr]['osmatch'][0]:
                            if zpScan[ip_addr]['osmatch'][0]['accuracy']=='100':
                                print('Operating system: '+zpScan[ip_addr]['osmatch'][0]['name'])
                            if zpScan[ip_addr]['osmatch'][0]['accuracy']!='100':
                                print('This is our best guess at the operating system: '+zpScan[ip_addr]['osmatch'][0]['name']+'\nAccuracy of guess: '+zpScan[ip_addr]['osmatch'][0]['accuracy']+'%')
                if 'hostscript' in zpScan[ip_addr]:
                    print('\nHost script results:')
                    for item in zpScan[ip_addr]['hostscript']:
                        if type(item)==dict:
                            print(' '+item['id']+': '+item['output'])
                    print('\n')
                if 'tcp' in zpScan[ip_addr]:
                    giantlist=[]
                    for item in zpScan[ip_addr]['tcp'].keys():
                        tablelist=[]
                        fixlist=[]
                        fixdict={}
                        bigstring=''
                        giantdict={}
                        version=zpScan[ip_addr]['tcp'][item]['version']
                        if zpScan[ip_addr]['tcp'][item]['version']!='':
                            version='Version:'+zpScan[ip_addr]['tcp'][item]['version']
                        printstatement2=(item,zpScan[ip_addr]['tcp'][item]['name'],zpScan[ip_addr]['tcp'][item]['state'],zpScan[ip_addr]['tcp'][item]['product'],version)
                        tablelist.append(printstatement2)
                        columns = ['Port', 'Service', 'Status', 'Product', 'Version']
                        avoidlist=['name', 'state', 'product', 'version']
                        for val in zpScan[ip_addr]['tcp'][item]:
                            if type(zpScan[ip_addr]['tcp'][item][val])!=dict:
                                if val not in avoidlist and zpScan[ip_addr]['tcp'][item][val]!='':
                                    fixdict[val]=zpScan[ip_addr]['tcp'][item][val]
                            if type(zpScan[ip_addr]['tcp'][item][val])==dict:
                                for thing in zpScan[ip_addr]['tcp'][item][val]:
                                    fixdict[thing]=str(zpScan[ip_addr]['tcp'][item][val][thing])
                        fixed_dict={}
                        for key in fixdict:
                            fixlist.append(str(key)+':'+str(fixdict[key]))
                        fixed_dict['Additional info']=fixlist
                        giantdict['Port']=item
                        giantdict['Service']=zpScan[ip_addr]['tcp'][item]['name']
                        giantdict['Status']=zpScan[ip_addr]['tcp'][item]['state']
                        giantdict['Product']=zpScan[ip_addr]['tcp'][item]['product']
                        giantdict['Version']=version                    
                        lencounter=0
                        for info in fixed_dict['Additional info']:
                            if len(info)<=70:
                                bigstring+=str(info)+'\n'
                            if len(info)>=70:
                                if '\n' not in info:
                                    if len(info)<=140:
                                        bigstring+=info[:70]+'\n'+info[70:]+'\n'
                                    if len(info)>140:
                                        bigstring+=info[:70]+'\n'+info[70:140]+'\n'+info[140:]
                                if '\n' in info:
                                    fixsplit=info.split('\n')
                                    for split in fixsplit:
                                        if len(split)>70 and len(split)<=140:
                                            bigstring+=split[:70]+'\n'+split[70:]+'\n'
                                        elif len(split)<=70:
                                            bigstring+=split+'\n'
                                        elif len(split)>140:
                                            stringfix=split
                                            lencounter=len(stringfix)
                                            while lencounter>0:
                                                if len(stringfix)>=140:                                         
                                                    bigstring+=stringfix[:70]+'\n'+stringfix[70:140]+'\n'
                                                    stringfix=stringfix[140:]
                                                    lencounter-=140
                                                if len(stringfix)<140 and len(stringfix)>70:                     
                                                    bigstring+=stringfix[:70]+'\n'+stringfix[70:]
                                                    stringfix=''
                                                    lencounter-=140
                                                if len(stringfix)<=70:
                                                    bigstring+=stringfix
                                                    stringfix=''
                                                    lencounter-=140
                                            bigstring+='\n'
                        giantdict['Additional info']=bigstring
                        giantlist.append(giantdict)
                    print(tabulate(giantlist, headers = "keys", tablefmt="fancy_grid"))
                    print(bigline)
                if 'tcp' not in zpScan[ip_addr]:
                    print('There does not appear to be any open TCP ports for this host')
                    print(bigline)
    
    if scan_numb=='6':
        while True:
            ip_addr6 = input("Please enter the target IP you would like to scan for vulnerabilities using CPEs:\nExample: 192.168.56.108\nIP --> ")
            if ipv4_regex.search(ip_addr6):
                print("The IP address entered is valid: ", ip_addr6)
                break

        version=zpScan.nmap_version()
        print(bigline)
        print("Nmap Version:   "+str(version[0])+'.'+str(version[1]))
        print('Please wait while your scan is completed. It may take some time.')
        zpScan.scan(hosts=ip_addr6, arguments='-sS -sV -A')
        print(bigline)

        cpe_exclude = ['cpe:/o:linux:linux_kernel', '', 'cpe:/a:samba:samba']

        print('Host: ',ip_addr6)
        if 'tcp' in zpScan[ip_addr6]:
            ports = zpScan[ip_addr6]['tcp'].keys()
            cve_table_lst = []

            for port in ports:
                cpe_var2 = ''
                if zpScan[ip_addr6]['tcp'][port]['version'] != '' and zpScan[ip_addr6]['tcp'][port]['cpe'] not in cpe_exclude:

                    # This is where the scan going out to NIST Starts
                    cpe_var = zpScan[ip_addr6]['tcp'][port]['cpe'].split('cpe:/')
                    cpe_var2 = cpe_var[1]
                
                    nvd_cve = ('https://services.nvd.nist.gov/rest/json/cves/1.0/')
                    prms = {'cpeMatchString' : 'cpe:2.3:' + cpe_var2,  'resultsPerPage' : 100}
                    full_url = ('https://services.nvd.nist.gov/rest/json/cves/1.0?cpeMatchString=cpe:2.3:' + cpe_var2 + '&resultsPerPage=2000')
                    
                    response = requests.get(nvd_cve, prms)

                    # Here is where the ouput of the NIST starts
                    response_json = json.loads(response.text)
                    total_results = response_json['totalResults']

                    #totals of severity starts here
                    severity_totals={'CRITICAL':0, 'HIGH':0, 'MEDIUM':0, 'LOW':0}
                    final_severity_totals={}
                    for cve2 in response_json['result']['CVE_Items']:
                        if 'baseMetricV3' in cve2['impact']:
                            severity_totals[cve2['impact']['baseMetricV3']['cvssV3']['baseSeverity']]+=1
                        else:
                            severity_totals[cve2['impact']['baseMetricV2']['severity']]+=1
                    final_severity_totals[port]=severity_totals

                    totals_output=('CVSS Severity Breakdown:\n CRITICAL: '+str(final_severity_totals[port]['CRITICAL'])+'\n'+' HIGH: '+str(final_severity_totals[port]['HIGH'])+'\n'+' MEDIUM: '+str(final_severity_totals[port]['MEDIUM'])+'\n'+' LOW: '+str(final_severity_totals[port]['LOW'])+'\n\n')
                    
                    output = ''
                    for cve in response_json['result']['CVE_Items'][:3]:
                        cve_id = cve['cve']['CVE_data_meta']['ID']
                        id = cve['cve']['CVE_data_meta']['ID']

                        if 'baseMetricV3' in cve['impact']:
                            base_output = 'Severity: {} \n Score: {} \n {}'.format(cve['impact']['baseMetricV3']['cvssV3']['baseSeverity'],cve['impact']['baseMetricV3']['cvssV3']['baseScore'], cve['impact']['baseMetricV3']['cvssV3']['vectorString'])
                        else:
                            base_output = 'Severity: {} \n Score: {} \n CVSS2: {}'.format(cve['impact']['baseMetricV2']['severity'], cve['impact']['baseMetricV2']['cvssV2']['baseScore'],cve['impact']['baseMetricV2']['cvssV2']['vectorString'])
                            
                        url = ('https://nvd.nist.gov/vuln/detail/' + str(id))

                        published_date = cve['publishedDate']
                        last_modified = cve['lastModifiedDate']
                        output += ' {} \n {} \n URL: {} \n Published: {} \n Last Modified: {} \n \n'.format(cve_id, base_output, url, published_date, last_modified)
                    if total_results == 0:
                        output_2 = ' Total CVE Results: {} \n'.format(total_results)
                    else:
                        output_2 = ' Total CVE Results: {} \n \n {} For complete json output please visit: \n {} \n \n Following are the latest 3 CVE\'s for this product:\n\n{}\n'.format(total_results,totals_output, full_url, output)

                    print_cve = (port, zpScan[ip_addr6]['tcp'][port]['state'], zpScan[ip_addr6]['tcp'][port]['name'], zpScan[ip_addr6]['tcp'][port]['cpe'], output_2)
                    cve_table_lst.append(print_cve)

            columns = ['Port', 'Status', 'Name', 'CPE', 'CVE Information']
            if cve_table_lst==[]:
                print('\nNo vulnerabilities found for CPEs on this host')
            else:
                print(tabulate(cve_table_lst, headers = columns, tablefmt="fancy_grid"))
        else:
            print('\nThere were no open TCP ports for this host')
    if scan_numb=='7':
        print('Exiting zpScan')
        exit()
    
    valid_scan_options=['1','2','3','4','5','6','7']
    if scan_numb not in valid_scan_options:
        print('\nPlease select a valid option\n')
        top_scan()
        
    if scan_numb != '6' and scan_numb != '7' and scan_numb in valid_scan_options:
        export_choice=input('\nWould you like to export this data in JSON format to a text file? (yes or no) --> ').lower()
        jsonoutput={}
        filename=str(scan_choice)+'_'+date_for_filename
        countdupes=0
        dirpath='./output'
        file_extension='.json'
        print(bigline)
        if export_choice=='yes':
            exists=os.path.exists(dirpath)
            if not exists:
                os.makedirs(dirpath)
                print('A directory has been created in the current directory named "output"')
            for host in zpScan.all_hosts():
                jsonoutput[str(host)]=zpScan[host]         
            if file_exists(dirpath+'/'+filename+file_extension) == True:
                stoploop=0
                while stoploop==0:
                    countdupes+=1
                    if file_exists(dirpath+'/'+filename+'_'+str(countdupes)+file_extension) == False:
                        filepath=dirpath+'/'+filename+'_'+str(countdupes)+file_extension
                        with open((filepath), "w") as output_file:
                            json.dump(jsonoutput, output_file)
                        filepath=filename+'_'+str(countdupes)+file_extension
                        stoploop=1
                print('Your JSON file has been created in the "output" directory with the name "'+filepath+'"')
            if file_exists(dirpath+'/'+filename+file_extension) == False:
                filepath=dirpath+'/'+filename+file_extension
                with open((filepath), "w") as output_file:      
                    json.dump(jsonoutput, output_file)
                filepath=filename+file_extension
                print('Your JSON file has been created in the "output" directory with the name "'+filepath+'"')
            print(bigline)
        elif export_choice=='no':
            print('You have selected: no\nNo file was created')
        else:
            print('Invalid response\nNo file created')
    
    # This is the code to loop back to the top
    print('\n')
    restart=input("Would you like to perform another scan? (yes or no) --> ").lower()
    if restart == "yes":
        top_scan()
    else:
        exit()

# This is where the code starts
top_scan()