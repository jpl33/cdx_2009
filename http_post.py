import json
import pandas as pd
import pymongo
import sys
import os
import csv
#import io
#import re
import subprocess
from subprocess import Popen, PIPE
from pathlib import Path
import getopt
import logging
import time
import datetime

home_dir='D:\\personal\\msc\\maccdc_2012\\'
#pcap_dir2= 'maccdc2012_00004\\'


logFormt='%(asctime)s: %(filename)s: %(lineno)d: %(message)s'
fh=logging.FileHandler(filename=home_dir+'error.log')
fh.setLevel(logging.DEBUG)
frmt=logging.Formatter(fmt=logFormt)
fh.setFormatter(frmt)
myLogger = logging.getLogger('maccdc')
myLogger.setLevel(logging.DEBUG)
myLogger.addHandler(fh)


client = pymongo.MongoClient('localhost')
db = client['local']

def get_db():
    return db

      
def  remove_collections(prefix):
     col_lst=get_db().collection_names() 
     for col in col_lst:
         if col.startswith(prefix):
             get_db().drop_collection(col)
              
              
def  is_pcap_dir(file_name):
    """simple function, user modifiable, to determine if a given file is in fact a PCAP file we want to process
    Currently just uses the naming convention"""
    
    if file_name.startswith('maccdc2012_'):
        return True
    else:
        return False
        

def main():
    
#   opts, args = getopt.getopt(sys.argv[1:],"h:t:")
#    for opt, arg in opts:
#        if opt in ("-h"):
#           home_dir = arg
#        elif opt in ("-t"):
#           tp = arg
### scan home directory, find pcap directories, where the snort CSV files are located     
    dl=next(os.walk(home_dir))[1]
    dl.sort()
    remove=[]
    for d in dl:
        if ( not is_pcap_dir(d)):
            remove.append(d)
            
###   open 'processed_***_file.txt' add processed files to the 'remove' list            
    prcs_file= open('processed_snort_bro_merge.txt', 'r+')
    for l in prcs_file.readlines():
        l=l.split("\n")[0]
        if len(l)>1:
            remove.append(l)
    for r in remove:
        dl.remove(r)

###    take the pcap directory, and look up the matching <pcap_dir_conn> collection in mogo db
    #for pcap_dir in dl:
    pcap_dir='maccdc2012_00002'

    coll_name=pcap_dir+'_http'
    try:
        collection_http=get_db().get_collection(coll_name)
    except Exception as e: 
        error=str(e)+':coll_name='+coll_name
        myLogger.error(error)
        sys.exit()     

###    initialize sleep() counters
    i=0
    old_i=0
    fl_lst=next(os.walk(home_dir))[2]
    fl_lst_pc=list()
    for ff in fl_lst:
        if ff.startswith(pcap_dir):
            if ff.endswith('.txt'):
               fl_lst_pc.append(ff)
    
    doc_tt=collection_http.find({'method':'POST'},sort=[('ts',1)])
    df_post=pd.DataFrame(list(doc_tt))
    df_post['post_content']=''
    with open(home_dir +fl_lst_pc[0],'r') as post_file:
        data = json.load(post_file)
        for dd in data:
            uid=(dd['_source']['layers']['ip']['ip.src'],dd['_source']['layers']['tcp']['tcp.srcport'],dd['_source']['layers']['ip']['ip.dst'],dd['_source']['layers']['frame']['frame.time_epoch'])
            if 'http.file_data' in dd['_source']['layers']['http'].keys():
                post_content=dd['_source']['layers']['http']['http.file_data']
            else:
                post_content=''
                continue
            # # reset 'doc' from former iteration
            doc=0
            doc=df_post.loc[(df_post.id_orig_h==uid[0])&(df_post.id_orig_p==int(uid[1]))&(df_post.id_resp_h==uid[2])]#&(df_post.ts==float(uid[3]))]
            if doc.empty:
                error='could not find http POST request:'+str(uid)
                myLogger.error(error)
            else:
                df_post.loc[df_post._id==doc._id.values[0],'post_content']=post_content
                collection_http.update_one({'_id':doc['_id'].values[0]},{'$set':{'post_content':post_content}})
        empty=df_post.loc[df_post.post_content=='']
        if empty.shape[0]>0:
            error='found empty POST requests in collection_http:'+str(empty.shape[0])
            myLogger.error(error)
            

    print('sugar')





main()