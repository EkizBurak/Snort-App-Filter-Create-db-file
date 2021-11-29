# -*- coding: utf-8 -*-
import subprocess
import hashlib
import re
import pathlib
import os

sql = open("/root/MYSQL/" + "app-db.sql", "w")
sql = open("/root/MYSQL/" + "app-db.sql", "a")

domainList=[]

category_list_en =  {'app-detect': 'app-detect', 'attack-responses': 'attack-responses', 'backdoor': 'backdoor', 'bad-traffic': 'bad-traffic', 'blacklist': 'blacklist', 'botnet-cnc': 'botnet-cnc', 'browser-chrome': 'browser-chrome', 'browser-firefox': 'browser-firefox', 'browser-ie': 'browser-ie', 'browser-other': 'browser-other', 'browser-plugins': 'browser-plugins', 'browser-webkit': 'browser-webkit', 'chat': 'chat', 'content-replace': 'content-replace', 'ddos': 'ddos', 'deleted': 'deleted', 'dns': 'dns', 'dos': 'dos', 'experimental': 'experimental', 'exploit-kit': 'exploit-kit', 'exploit': 'exploit', 'file-executable': 'file-executable', 'file-flash': 'file-flash', 'file-identify': 'file-identify', 'file-image': 'file-image', 'file-java': 'file-java', 'file-multimedia': 'file-multimedia', 'file-office': 'file-office', 'file-other': 'file-other', 'file-pdf': 'file-pdf', 'finger': 'finger', 'ftp': 'ftp', 'icmp-info': 'icmp-info', 'icmp': 'icmp', 'imap': 'imap', 'indicator-compromise': 'indicator-compromise', 'indicator-obfuscation': 'indicator-obfuscation', 'indicator-scan': 'indicator-scan', 'indicator-shellcode': 'indicator-shellcode', 'info': 'info', 'local': 'local', 'malware-backdoor': 'malware-backdoor', 'malware-cnc': 'malware-cnc', 'malware-other': 'malware-other', 'malware-tools': 'malware-tools', 'misc': 'misc', 'multimedia': 'multimedia', 'mysql': 'mysql', 'netbios': 'netbios', 'nntp': 'nntp', 'oracle': 'oracle', 'os-linux': 'os-linux', 'os-mobile': 'os-mobile', 'os-other': 'os-other', 'os-windows': 'os-windows', 'other-ids': 'other-ids', 'p2p': 'p2p', 'phishing-spam': 'phishing-spam', 'policy-multimedia': 'policy-multimedia', 'policy-other': 'policy-other', 'policy-spam': 'policy-spam', 'policy': 'policy', 'pop2': 'pop2', 'pop3': 'pop3', 'protocol-dns': 'protocol-dns', 'protocol-finger': 'protocol-finger', 'protocol-ftp': 'protocol-ftp', 'protocol-icmp': 'protocol-icmp', 'protocol-imap': 'protocol-imap', 'protocol-nntp': 'protocol-nntp', 'protocol-other': 'protocol-other', 'protocol-pop': 'protocol-pop', 'protocol-rpc': 'protocol-rpc', 'protocol-scada': 'protocol-scada', 'protocol-services': 'protocol-services', 'protocol-snmp': 'protocol-snmp', 'protocol-telnet': 'protocol-telnet', 'protocol-tftp': 'protocol-tftp', 'protocol-voip': 'protocol-voip', 'pua-adware': 'pua-adware', 'pua-other': 'pua-other', 'pua-p2p': 'pua-p2p', 'pua-toolbars': 'pua-toolbars', 'rpc': 'rpc', 'rservices': 'rservices', 'scada': 'scada', 'scan': 'scan', 'server-apache': 'server-apache', 'server-iis': 'server-iis', 'server-mail': 'server-mail', 'server-mssql': 'server-mssql', 'server-mysql': 'server-mysql', 'server-oracle': 'server-oracle', 'server-other': 'server-other', 'server-samba': 'server-samba', 'server-webapp': 'server-webapp', 'shellcode': 'shellcode', 'smtp': 'smtp', 'snmp': 'snmp', 'specific-threats': 'specific-threats', 'spyware-put': 'spyware-put', 'sql': 'sql', 'telnet': 'telnet', 'tftp': 'tftp', 'virus': 'virus', 'voip': 'voip', 'web-activex': 'web-activex', 'web-attacks': 'web-attacks', 'web-cgi': 'web-cgi', 'web-client': 'web-client', 'web-coldfusion': 'web-coldfusion', 'web-frontpage': 'web-frontpage', 'web-iis': 'web-iis', 'web-misc': 'web-misc', 'web-php': 'web-php', 'x11': 'x11', "community" : "community", "policy-social" : "policy-social", "os-solaris" : "os-solaris"}


category_list_tr = {'app-detect': 'app-detect', 'attack-responses': 'attack-responses', 'backdoor': 'backdoor', 'bad-traffic': 'bad-traffic', 'blacklist': 'blacklist', 'botnet-cnc': 'botnet-cnc', 'browser-chrome': 'browser-chrome', 'browser-firefox': 'browser-firefox', 'browser-ie': 'browser-ie', 'browser-other': 'browser-other', 'browser-plugins': 'browser-plugins', 'browser-webkit': 'browser-webkit', 'chat': 'chat', 'content-replace': 'content-replace', 'ddos': 'ddos', 'deleted': 'deleted', 'dns': 'dns', 'dos': 'dos', 'experimental': 'experimental', 'exploit-kit': 'exploit-kit', 'exploit': 'exploit', 'file-executable': 'file-executable', 'file-flash': 'file-flash', 'file-identify': 'file-identify', 'file-image': 'file-image', 'file-java': 'file-java', 'file-multimedia': 'file-multimedia', 'file-office': 'file-office', 'file-other': 'file-other', 'file-pdf': 'file-pdf', 'finger': 'finger', 'ftp': 'ftp', 'icmp-info': 'icmp-info', 'icmp': 'icmp', 'imap': 'imap', 'indicator-compromise': 'indicator-compromise', 'indicator-obfuscation': 'indicator-obfuscation', 'indicator-scan': 'indicator-scan', 'indicator-shellcode': 'indicator-shellcode', 'info': 'info', 'local': 'local', 'malware-backdoor': 'malware-backdoor', 'malware-cnc': 'malware-cnc', 'malware-other': 'malware-other', 'malware-tools': 'malware-tools', 'misc': 'misc', 'multimedia': 'multimedia', 'mysql': 'mysql', 'netbios': 'netbios', 'nntp': 'nntp', 'oracle': 'oracle', 'os-linux': 'os-linux', 'os-mobile': 'os-mobile', 'os-other': 'os-other', 'os-windows': 'os-windows', 'other-ids': 'other-ids', 'p2p': 'p2p', 'phishing-spam': 'phishing-spam', 'policy-multimedia': 'policy-multimedia', 'policy-other': 'policy-other', 'policy-spam': 'policy-spam', 'policy': 'policy', 'pop2': 'pop2', 'pop3': 'pop3', 'protocol-dns': 'protocol-dns', 'protocol-finger': 'protocol-finger', 'protocol-ftp': 'protocol-ftp', 'protocol-icmp': 'protocol-icmp', 'protocol-imap': 'protocol-imap', 'protocol-nntp': 'protocol-nntp', 'protocol-other': 'protocol-other', 'protocol-pop': 'protocol-pop', 'protocol-rpc': 'protocol-rpc', 'protocol-scada': 'protocol-scada', 'protocol-services': 'protocol-services', 'protocol-snmp': 'protocol-snmp', 'protocol-telnet': 'protocol-telnet', 'protocol-tftp': 'protocol-tftp', 'protocol-voip': 'protocol-voip', 'pua-adware': 'pua-adware', 'pua-other': 'pua-other', 'pua-p2p': 'pua-p2p', 'pua-toolbars': 'pua-toolbars', 'rpc': 'rpc', 'rservices': 'rservices', 'scada': 'scada', 'scan': 'scan', 'server-apache': 'server-apache', 'server-iis': 'server-iis', 'server-mail': 'server-mail', 'server-mssql': 'server-mssql', 'server-mysql': 'server-mysql', 'server-oracle': 'server-oracle', 'server-other': 'server-other', 'server-samba': 'server-samba', 'server-webapp': 'server-webapp', 'shellcode': 'shellcode', 'smtp': 'smtp', 'snmp': 'snmp', 'specific-threats': 'specific-threats', 'spyware-put': 'spyware-put', 'sql': 'sql', 'telnet': 'telnet', 'tftp': 'tftp', 'virus': 'virus', 'voip': 'voip', 'web-activex': 'web-activex', 'web-attacks': 'web-attacks', 'web-cgi': 'web-cgi', 'web-client': 'web-client', 'web-coldfusion': 'web-coldfusion', 'web-frontpage': 'web-frontpage', 'web-iis': 'web-iis', 'web-misc': 'web-misc', 'web-php': 'web-php', 'x11': 'x11', "community" : "community", "policy-social" : "policy-social", "os-solaris" : "os-solaris"}



categoriesID = 1
categoriesList = os.listdir("/usr/local/etc/snort/rules")
for i in categoriesList:
    if not i.endswith('.rules'):
        categoriesList.remove(i)
        continue
    categoriesName=i.split(".")[0].split("_")[1]
    sqlExecute = """INSERT INTO `avrestor_apps`.`Categories` (`CategoryID`, `CategoryNameTR`, `CategoryNameEN`) VALUES ('{}', '{}', '{}');""".format(categoriesID, category_list_tr[categoriesName],category_list_en[categoriesName])
    sql.write(sqlExecute + "\n")
    with open(f"/usr/local/etc/snort/rules/{i}") as f:
        domainList=f.read().split("\n")
    for x in domainList:
        try:
            sid=x.split("sid:")[1].split(";")[0]
            try:
                sid=int(sid)
            except:
                continue
            appName=category_list_tr[x.split("msg:")[1].split(" ")[0].replace('"',"").lower()]
            rule=x
            sqlExecute = """INSERT INTO `avrestor_apps`.`Applications` (`ID`, `CategoryID`, `AppName`, `Rule`) VALUES ('{}', '{}', '{}', '{}');""".format(sid,categoriesID,appName,rule.replace('alert ', '').replace('$HOME_NET', '[IPADRESI]').replace("'",'"'))
            sql.write(sqlExecute + "\n")
        except:
            pass
    categoriesID += 1