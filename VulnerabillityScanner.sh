#!/bin/bash

METASPLOITABLE_2_IP="10.38.1.112"
METASPLOITABLE_3_IP="10.38.1.111"
LOG_FILE="/home/kali/Desktop/scanlog"

echo "======================" >> $LOG_FILE
echo " Scan Results - $(date) " >> $LOG_FILE
echo "======================" >> $LOG_FILE
echo "" >> $LOG_FILE

run_nmap_scan() {
    local target_ip=$1
    echo "======================" >> $LOG_FILE
    echo " Scanning target: $target_ip " >> $LOG_FILE
    echo "======================" >> $LOG_FILE
    echo "" >> $LOG_FILE

    echo "== Apache Struts CVE-2017-5638 ==" >> $LOG_FILE
    echo "Timestamp: $(date)" >> $LOG_FILE
    nmap --script=http-vuln-cve2017-5638.nse -p 80 $target_ip >> $LOG_FILE 2>&1
    echo "" >> $LOG_FILE

    echo "== SMB Vulnerability MS17-010 (EternalBlue) ==" >> $LOG_FILE
    echo "Timestamp: $(date)" >> $LOG_FILE
    nmap --script=smb-vuln-ms17-010.nse -p 445 $target_ip >> $LOG_FILE 2>&1
    echo "" >> $LOG_FILE

    echo "== vsFTPd Backdoor ==" >> $LOG_FILE
    echo "Timestamp: $(date)" >> $LOG_FILE
    nmap --script=ftp-vsftpd-backdoor.nse -p 21 $target_ip >> $LOG_FILE 2>&1
    echo "" >> $LOG_FILE

    echo "== MySQL Vulnerabilities (CVE-2012-2122) ==" >> $LOG_FILE
    echo "Timestamp: $(date)" >> $LOG_FILE
    nmap --script=mysql-vuln-cve2012-2122.nse -p 3306 $target_ip >> $LOG_FILE 2>&1
    echo "" >> $LOG_FILE

    echo "== Apache Tomcat CVE-2017-5638 ==" >> $LOG_FILE
    echo "Timestamp: $(date)" >> $LOG_FILE
    nmap --script=http-vuln-cve2017-5638.nse -p 8080 $target_ip >> $LOG_FILE 2>&1
    echo "" >> $LOG_FILE

    echo "== Weak SSH Authentication ==" >> $LOG_FILE
    echo "Timestamp: $(date)" >> $LOG_FILE
    nmap --script=ssh-auth-methods.nse -p 22 $target_ip >> $LOG_FILE 2>&1
    echo "" >> $LOG_FILE

    echo "== HTTP Vulnerabilities ==" >> $LOG_FILE
    echo "Timestamp: $(date)" >> $LOG_FILE
    nmap --script=http-vuln* -p 80,443 $target_ip >> $LOG_FILE 2>&1
    echo "" >> $LOG_FILE

    echo "== SMB Vulnerabilities ==" >> $LOG_FILE
    echo "Timestamp: $(date)" >> $LOG_FILE
    nmap --script=smb-vuln* -p 445 $target_ip >> $LOG_FILE 2>&1
    echo "" >> $LOG_FILE

    echo "== Known CVEs ==" >> $LOG_FILE
    echo "Timestamp: $(date)" >> $LOG_FILE
    nmap --script=cve-search --script-args=cve-search-db=/usr/share/nmap/nse/cve-search-db -p 80,443,445 $target_ip >> $LOG_FILE 2>&1
    echo "" >> $LOG_FILE
}

run_nmap_scan $METASPLOITABLE_2_IP
run_nmap_scan $METASPLOITABLE_3_IP

echo "======================" >> $LOG_FILE
echo " Scan completed! " >> $LOG_FILE
echo " Results are logged to $LOG_FILE." >> $LOG_FILE
