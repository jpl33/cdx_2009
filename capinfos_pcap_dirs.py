#!/usr/bin/env python

import os
import datetime
import subprocess
import sys
import pathlib
import pathlib
import pandas as pd

from subprocess import Popen, PIPE
from os import path
from pathlib import Path
import logging



#pcap_dir = "/mnt/hgfs/cdx_2009/sandbox_win"
home_dir='D:\\personal\\msc\\maccdc_2012\\'
pcap_dir= 'maccdc2012_00003\\'
pcap=(".pcap",".dmp",",pcapng")
conn_frmt=['ts','uid','id.orig_h','id.orig_p','id.resp_h','id.resp_p','proto','service','duration','orig_bytes','resp_bytes','conn_state','local_orig','local_resp','missed_bytes','history','orig_pkts','orig_ip_bytes','resp_pkts','resp_ip_bytes','tunnel_parents','orig_cc','resp_cc','sensorname']
snrt_frmt=['timestamp','sig_generator','sig_id','sig_rev','msg','proto','src','srcport','dst','dstport','ethsrc','ethdst','ethlen','tcpflags','tcpseq','tcpack','tcplen','tcpwindow','ttl','tos','id','dgmlen','iplen','icmptype','icmpcode','icmpid','icmpseq']

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
    print ("Pcap files dir %s" %home_dir)    
    pcap_file_list = os.listdir(home_dir)
    pcap_file_list.sort()
    print ("- files found %s"%pcap_file_list)
    out_file= open('pcap_info.txt', 'r+')
    prcf_file= open('processed_files.txt', 'r+')
    is_header(out_file)
    # go through list and remove entries that aren't files we care about
    to_be_removed = []
    
    # add your list to the var so that we exclude pcap files 
    #to_be_removed = ['snort.log.xxxxxx','snort.log.xxxxxx']
    
    for f in pcap_file_list:
        if not is_pcap(f):
            to_be_removed.append(f)
    for l in prcf_file.readlines():
        l=l.split("\n")[0]
        to_be_removed.append(l)
    
    
    for f in to_be_removed:
        print ("Not pcap so not processing %s"%f)
        pcap_file_list.remove(f)
    
    num_pcap_files = len(pcap_file_list)
    pcap_file_dict = {}
        
    #print pcap_file_dict
      
    print ("NUMBER OF FILES IN FOLDER")
    print (len(pcap_file_list))
    alrt_sum=pd.DataFrame()   
    nmm=[]
    sdpwd="S3cur!ty"
    print ("running snort ")
    for pf in pcap_file_list:
         print ("current file : %s" % pf)
        # since snort takes so long to start up, only run it once at the end on all the pcap files at once
         pcap_name =pf.split(".")[0]
         pcap_snort=(home_dir + pf)         

         #is__dir(pcap_dir,output_dirname)
         if (hdr==0):
            # capinfos_cmd = "sudo capinfos -m -a -e -r -T %s" %(pcap_snort)
            win_cmd="capinfos -m -a -e -r -T %s" %(pcap_snort)
         else:
             #capinfos_cmd = "sudo capinfos -m -a -e -T %s" %(pcap_snort)
             win_cmd="capinfos -m -a -e -T %s" %(pcap_snort)
             
         #sn=capinfos_cmd.split()
         
         wn_cmd=win_cmd.split()
         #run_capinfos = subprocess.Popen(['sudo', '-S']+sn, stdin=PIPE, stderr=PIPE,universal_newlines=True)
         #run_capinfos = subprocess.check_output(['sudo', '-S']+sn, stdin=PIPE, stderr=PIPE,universal_newlines=True)
         
         run_win_cmd = subprocess.check_output(wn_cmd, stdin=PIPE, stderr=PIPE,universal_newlines=True)
         
         df = pd.read_csv(home_dir+pcap_dir +'conn.log',sep='\t',comment='#',names=conn_frmt)
         srvc=list(df['service'].unique())
         srvc_nm=df['service'].value_counts()
         alrt = pd.read_csv(home_dir+pcap_dir +'alert.csv',sep=',',comment='#',names=snrt_frmt)
         alrt_nm=alrt['msg'].value_counts()
         alrt_sig=alrt['sig_id'].value_counts()
         
         out_file.write(run_win_cmd)
         out_file.write(srvc_nm.to_string())
         out_file.write(alrt_nm.to_string())
         out_file.write(alrt_sig.to_string())

         out_file.flush()


            
        
    
    
    
    
    
main()
