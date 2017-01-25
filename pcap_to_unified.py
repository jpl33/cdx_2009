#!/usr/bin/env python

import os
import datetime
import subprocess
import sys
from subprocess import Popen, PIPE
from os import path

pcap_dir = "/mnt/hgfs/cdx_2009/sandbox_win"
pcap=(".pcap",".dmp",",pcapng")

def is_pcap(file_name):
    """simple function, user modifiable, to determine if a given file is in fact a PCAP file we want to process
    Currently just uses the naming convention"""
    
    if file_name.endswith(pcap):
        return True
    else:
        return False
        
def main():
    
    
    # Get list of PCAP files to ready to be processed - if ctime of file is less than ctime of next file in file ring buffer
    print ("Pcap files dir %s" %pcap_dir)    
    pcap_file_list = os.listdir(pcap_dir)
    pcap_file_list.sort()
    print ("- files found %s"%pcap_file_list)
    
    # go through list and remove entries that aren't files we care about
    to_be_removed = []
    
    # add your list to the var so that we exclude pcap files 
    #to_be_removed = ['snort.log.xxxxxx','snort.log.xxxxxx']
    
    for f in pcap_file_list:
        if not is_pcap(f):
            to_be_removed.append(f)
    for f in to_be_removed:
        print ("Not pcap so not processing %s"%f)
        pcap_file_list.remove(f)
    
    num_pcap_files = len(pcap_file_list)
    pcap_file_dict = {}
        
    #print pcap_file_dict
      
    print ("NUMBER OF FILES IN FOLDER")
    print (len(pcap_file_list))
      
    sdpwd="S3cur!ty"
    print ("running snort ")
    out_file= open('processed_files.txt', 'a') 
    pcap_snort=pcap_dir
    for pf in pcap_file_list:
         print ("current file : %s" % pf)
        # since snort takes so long to start up, only run it once at the end on all the pcap files at once
         output_dirname =pf.split(".")[0]
         pcap_snort+=("/" + pf)

      #snort alert file success
      #sudo snort   -c /etc/nsm/security-onion-eth0/snort.conf  -r "2009-04-20-09-05-46.dmp" -l /mnt/hgfs/cdx_2009/sandbox_win   --daq pcap --daq-mode read-file 
      #sudo snort   -c /etc/nsm/security-onion-eth0/snort.conf  -r %s -l %s   --daq pcap --daq-mode read-file" %(pcap_file_for_snort, output_dirname)


      # barnyard cmd
      #sudo barnyard2 -c /etc/nsm/security-onion-eth0/barnyard2.conf  -o "snort.unified2.1483036626" -U  -l /mnt/hgfs/cdx_2009/sandbox_win/

         snort_cwd = pcap_dir + "/" + output_dirname

         snort_cmd = "sudo snort   -c /etc/nsm/security-onion-eth0/snort.conf  -r %s -l %s   --daq pcap --daq-mode read-file" %(pcap_snort, snort_cwd)
         sn=snort_cmd.split()
         run_snort = subprocess.Popen(['sudo', '-S']+sn, stdin=PIPE, stderr=PIPE,universal_newlines=True)
         sudo_prompt = run_snort.communicate(sdpwd + '\n')[1]            
         run_snort.wait()
         pcap_snort+= ("\n")
         out_file.write(pcap_snort)
         out_file.flush()


            
        
    
    
    
    
    
main()
