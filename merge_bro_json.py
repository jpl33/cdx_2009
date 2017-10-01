# -*- coding: utf-8 -*-
"""
Created on Thu Mar 30 14:20:31 2017

@author: root
"""

#!/usr/bin/python

import json
import pandas as pd
import pymongo
import sys
import os
#import csv
#import io
#import re
import itertools
import getopt
import logging
import time


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




#file = sys.argv[1]
#colname = sys.argv[2]
#skip=0
#with open(home_dir+pcap_dir +'ntlm.txt', "r") as f:         
#    lines=0    
#    for line in f.readlines():
#            li = line.lstrip()
#            if  li.startswith("#"):
#                lines+= 1
#            else :
#             break
#    skip=lines
#    print(skip)

mongo_fields={"id.orig_h":"id_orig_h","id.orig_p":"id_orig_p","id.resp_h":"id_resp_h","id.resp_p":"id_resp_p"}

service_log_files={'ntlm':'ntlm.json',
                   'http':'http.json',
                   'ftp':'ftp.json',
                   #'ftp-data':'ftp.json',
                   'dns':'dns.json',
                   'dhcp':'dhcp.json',
                   'sip':'sip.json',
                   'ssh':'ssh.json',
                   'smb':['smb_files.json','smb_mapping.json'],
                   'dce_rpc':'dce_rpc.json',
                   'krb_tcp':'kerberos.json',
                   'mysql':'mysql.json',
                   'snmp':'snmp.json',
                   'ssl':'ssl.json'}
collection_filters={'default':[('uid', pymongo.ASCENDING),('ts', pymongo.ASCENDING)]   ,
                    'ntlm':[('uid', pymongo.ASCENDING),('ts', pymongo.ASCENDING),('username', pymongo.ASCENDING)]   ,
                    'sip':[('uid', pymongo.ASCENDING),('ts', pymongo.ASCENDING),('status_msg', pymongo.ASCENDING)]   ,
                    'ftp':[('uid', pymongo.ASCENDING),('ts', pymongo.ASCENDING),('command', pymongo.ASCENDING)]   ,           
                    'http':[('uid', pymongo.ASCENDING),('ts', pymongo.ASCENDING),('uri_length', pymongo.ASCENDING),('trans_depth', pymongo.ASCENDING)]   ,
                    'dns':[('uid', pymongo.ASCENDING),('ts', pymongo.ASCENDING),('trans_id', pymongo.ASCENDING)]   ,
                    'conn':[('id_orig_h',pymongo.ASCENDING),('id_orig_p',pymongo.ASCENDING),('id_resp_h',pymongo.ASCENDING),('id_resp_p',pymongo.ASCENDING)]}
client = pymongo.MongoClient('localhost')
db = client['local']
#collection = db['temp']
#collection_pcap = db['pcap03']

def get_db():
    return db


def mongo_json(mydict):
    for key,value in mydict.items():
           kk=key.split('.')
           kd=''
           if len(kk)>1:
               for k in kk:
                   kd=kd+k+'_'
               kd=kd[:-1]
               mydict[kd]=mydict.pop(key)   
               
      
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
        
def  load_service(home_dir,file,pcap_dir,service,lst_flag):
     # 'file' is the full-path file name of the json file
     # 'service' is the BRO service name: 'dns','http','krb_tcp'
     if lst_flag==True:
         if pcap_dir+'_'+service in db.collection_names():
             colt=db[pcap_dir+'_'+service]
         else:   
             colt=pymongo.collection.Collection(db,pcap_dir+'_'+service,create=True)
     else:   
         colt=pymongo.collection.Collection(db,pcap_dir+'_'+service,create=True)
     
     
     i=0
     old_i=0
     file=home_dir+pcap_dir+'//'+file
     
     with open(file,'r') as srvc_f:
        for line in srvc_f:
            ln=json.loads(line)
            ln['service']=service
            mongo_json(ln)
            i+=1
            if i-old_i>10000:
                old_i=i
                time.sleep(20)
                slp_msg='sleeping now'+':pcap_dir='+pcap_dir+':svc='+service+':i='+str(i)
                myLogger.error(slp_msg)

            ln['match']=0
            if service=='http':
                if 'uri' in ln.keys():
                    ln['uri_length']=len(ln['uri'])
                else:
                    ln['uri_length']=0
            try:
                colt.insert_one(ln)
            except Exception as e:
                if not service=='dns':
                    error=str(e)+':svc='+str(ln)+':service='+service+':index='+str(i)
                    myLogger.error(error)
                    exit
     return colt
            

def main():
    
    opts, args = getopt.getopt(sys.argv[1:],"h:t:")
    for opt, arg in opts:
        if opt in ("-h"):
           home_dir = arg
        elif opt in ("-t"):
           tp = arg
    
    
    dl=next(os.walk(home_dir))[1]
    dl.sort()
    remove=[]
    for d in dl:
        if ( not is_pcap_dir(d)):
            remove.append(d)
    prcs_file= open('processed_merge_files.txt', 'r+')
    for l in prcs_file.readlines():
        l=l.split("\n")[0]
        remove.append(l)
    for r in remove:
        dl.remove(r)

    #client = pymongo.MongoClient('localhost')
    #db = client['local']
    #collection = get_db()['temp']
    #collection_pcap = get_db()['pcap02']
    
    for pcap_dir in dl:
        coll_name=pcap_dir+'_conn'
        if not coll_name in get_db().collection_names():
            collection_pcap=pymongo.collection.Collection(get_db(),coll_name,create=True)
            coll_count=0
            collections={}
        else:
            collection_pcap=get_db().get_collection(coll_name)
            coll_count=get_db().get_collection(coll_name).count()
            col_lst=get_db().collection_names() 
            
        result = db[collection_pcap.name].create_index(collection_filters['conn'])
        
        i=0
        old_i=0
        with open(home_dir+pcap_dir +'\\conn.json','r') as conn_f:
            for line in itertools.islice(conn_f, coll_count,None):
            #for line in conn_f:   
                ln=json.loads(line)
                i+=1
                if i-old_i>100000:
                    old_i=i
                    time.sleep(20)
                    slp_msg='sleeping now'+':pcap_dir='+pcap_dir+':svc='+'conn'+':i='+str(i)
                    myLogger.error(slp_msg)
                mongo_json(ln)
                if 'service' in ln.keys():
                    for svc in ln['service'].split(','):
                        if svc not in collections.keys():
                            try:
                            #if svc in service_log_files.keys():
                                fnm=service_log_files[svc]
                            except Exception as e:
                                error=str(e)+':svc='+str(svc)+':pcap_dir='+pcap_dir+':index='+str(i)
                                myLogger.error(error)
                                continue
                            if type(fnm)==list:
                                for sfnm in fnm:
                                    colt=load_service(home_dir,sfnm,pcap_dir,svc,True)
                                    collections[svc]=colt
                            else:
                                colt=load_service(home_dir,fnm,pcap_dir,svc,False)
                                collections[svc]=colt
                                
                        colt=collections[svc]
                        for doc in colt.find({'uid':ln['uid'],'service':svc}):
                            if not doc==None:
                                if svc in service_log_files:
                                    #    collection.update({'_id':doc['_id']},{'$addToSet':{svc:ln}})
                                    colt.update_one({'_id':doc['_id']},{'$set':{'match':1}})
                                    if not svc in ln.keys():
                                        ln.setdefault(svc,[])
                                    ln[svc].append(doc['_id'])
                
                try:
                    collection_pcap.insert_one(ln)
                except Exception as e:
                    error=str(e)+':cn='+str(ln)+':index='+str(i)
                    myLogger.error(error)
                    exit
                    
        prcs_file.write("\n"+pcap_dir)
        prcs_file.flush()
   
#    conn_data[0].keys()
#    query=[ntlm_data[0]['id.orig_h'],ntlm_data[0]['id.orig_p'],ntlm_data[0]['id.resp_h'],ntlm_data[0]['id.resp_p']]
#    
#    nt_json=[]
    #fconn = open(home_dir+pcap_dir +'conn2.json', 'r')
    
    #for it in ijson.items(fconn, 'item'):
    #    if ('ntlm' in it['service']):
        #if ((it['id.orig_h']==ntlm_data[0]['id.orig_h']) & (it['id.orig_p']==ntlm_data[0]['id.orig_p'])):
    #       nt_json.append(it)
    #for nt in ntlm_data:
    #    fconn = open(home_dir+pcap_dir +'conn.json', 'rb')
    #    for it in ijson.items(fconn, 'item'):
    #        if ((it['id.orig_h']==nt['id.orig_h']) & (it['id.orig_p']==nt['id.orig_p'])):
    #            print(it)
    #       print(nt['id.orig_h'])
    
    
    
    
    



    
    
        
    


main()


# ntlm_data = []
#    with open(home_dir+pcap_dir +'ntlm.json','r') as ntlm_f:
#           for line in itertools.islice(ntlm_f, 0,6):
#              lin = json.loads(line)
#              lin['match']=0
#              ntlm_data.append(lin)
#    dns_data=[]
#    with open(home_dir+pcap_dir +'dns.json','r') as dns_f:
#        for line in itertools.islice(dns_f, 0,2):
#            dns_data.append(json.loads(line))
            

#    read  line from json file, filter on src_ip and src_port, extract time stamp
#df=pd.read_json(home_dir+pcap_dir +'conn.json',orient= 'records',lines=True)
#df.columns
#query2=df.columns
#line1=df[(df['id.orig_h']==query[0]) & (df['id.orig_p']==query[1])]
#'%.2f' % line1['ts']
#'ntlm' in str(line1['service'].values[0]).split(',')

#        transform unix timestamp to date_time, and backwards
#import datetime
#print(
#    datetime.datetime.fromtimestamp(
#        float('%.2f'% line1['ts'])
#    ).strftime('%Y-%m-%d %H:%M:%S.%f')
#)
#    
#d = datetime.date(2015,1,5)

#unixtime = time.mktime(d.timetuple())

#        iterate on a directory files, filtering for json files
#    for d in itertools.islice(dl,0,3):
#        ddl=next(os.walk(home_dir+'\\'+d))[2]
#        ddl.sort(reverse=True)
#        remove=[]
#        for fnm in ddl:
#            ff=fnm.split('.')
#            if len(ff)>=2:
#                if not ff[1] in 'json':
#                    remove.append(fnm)
#            else:
#                remove.append(fnm)
#        for r in remove:
#            ddl.remove(r)
#        print(ddl)