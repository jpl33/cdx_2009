#!/usr/bin/env python

import os
import datetime
import subprocess
import sys
import pathlib
import pathlib

from subprocess import Popen, PIPE
from os import path
from pathlib import Path
import logging



pcap_dir = "/mnt/hgfs/cdx_2009/sandbox_win"
pcap=(".pcap",".dmp",",pcapng")

def is_pcap(file_name):
    """simple function, user modifiable, to determine if a given file is in fact a PCAP file we want to process
    Currently just uses the naming convention"""
    
    if file_name.endswith(pcap):
        return True
    else:
        return False

def is__dir(parent, dir_name):
    if (not Path(dir_name).is_dir() ):
         pp1=Path(parent+'/'+dir_name).mkdir()
hdr=0
def is_header(file):
    if (file.readline().split(" ")[0]=="File"):
       hdr=1
       
    
        
        
def main():
    
    
    # Get list of PCAP files to ready to be processed - if ctime of file is less than ctime of next file in file ring buffer
    print ("Pcap files dir %s" %pcap_dir)    
    pcap_file_list = os.listdir(pcap_dir)
    pcap_file_list.sort()
    print ("- files found %s"%pcap_file_list)
    out_file= open('pcap_info.txt', 'r+') 
    is_header(out_file)
    # go through list and remove entries that aren't files we care about
    to_be_removed = []
    
    # add your list to the var so that we exclude pcap files 
    #to_be_removed = ['snort.log.xxxxxx','snort.log.xxxxxx']
    
    for f in pcap_file_list:
        if not is_pcap(f):
            to_be_removed.append(f)
#    for l in out_file.readlines():
#        l=l.split("\n")[0]
#        to_be_removed.append(l)
#    
    
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
    for pf in pcap_file_list:
         print ("current file : %s" % pf)
        # since snort takes so long to start up, only run it once at the end on all the pcap files at once
         output_dirname =pf.split(".")[0]
         pcap_snort=(pcap_dir+"/"+output_dirname+"/" + pf)         

         #is__dir(pcap_dir,output_dirname)
         if (hdr==0):
             capinfos_cmd = "sudo capinfos -m -a -e -r -T %s" %(pcap_snort)
         else:
             capinfos_cmd = "sudo capinfos -m -a -e -T %s" %(pcap_snort)
             
         sn=capinfos_cmd.split()
         #run_capinfos = subprocess.Popen(['sudo', '-S']+sn, stdin=PIPE, stderr=PIPE,universal_newlines=True)
         run_capinfos = subprocess.check_output(['sudo', '-S']+sn, stdin=PIPE, stderr=PIPE,universal_newlines=True)
       
         out_file.write(run_capinfos)
         out_file.flush()


            
        
    
    
    
    
    
main()
