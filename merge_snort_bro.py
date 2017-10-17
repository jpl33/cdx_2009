
# coding: utf-8

# In[1]:


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
import csv
#import io
#import re
import itertools
import getopt
import logging
import time
import datetime
from IPython.core.debugger import Pdb;


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



snrt_frmt=['timestamp','sig_generator','sig_id','sig_rev','msg','proto','src','srcport','dst','dstport','ethsrc','ethdst','ethlen','tcpflags','tcpseq','tcpack','tcplen','tcpwindow','ttl','tos','id','dgmlen','iplen','icmptype','icmpcode','icmpid','icmpseq']

vuln_service={'http':0,'ftp':0,'dns':0,'dhcp':0,'sip':0,'ssh':0,'smb':0,'dce_rpc':0,'mysql':0,'snmp':0,'ssl':0}

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
            
def   time_to_ts(row_ts):  
      strd=row_ts[:-2]
      dt=datetime.datetime.strptime(strd,'%m/%d/%y-%H:%M:%S.%f')
      snrt_ts = dt.timestamp()
      snrt_ts=snrt_ts+7200
      return snrt_ts

#dt=datetime.datetime.strptime(dd['timestamp'],'%m/%d/%Y-%H:%M:%S.%f')   
#unixtime = time.mktime(d.timetuple())



    
    



# In[ ]:


def main():
    
#   opts, args = getopt.getopt(sys.argv[1:],"h:t:")
#    for opt, arg in opts:
#        if opt in ("-h"):
#           home_dir = arg
#        elif opt in ("-t"):
#           tp = arg
    
    dl=next(os.walk(home_dir))[1]
    dl.sort()
    remove=[]
    for d in dl:
        if ( not is_pcap_dir(d)):
            remove.append(d)
    prcs_file= open('processed_snort_bro_merge.txt', 'r+')
    for l in prcs_file.readlines():
        l=l.split("\n")[0]
        remove.append(l)
    for r in remove:
        dl.remove(r)
    
    for pcap_dir in dl:
        coll_name=pcap_dir+'_conn'
        try:
            collection_pcap=get_db().get_collection(coll_name)
        except Exception as e: 
            error=str(e)+':coll_name='+coll_name
            myLogger.error(error)
            exit     
        
        i=0
        old_i=0
        
        
        with open(home_dir+pcap_dir +'\\alert.csv','r') as alrt_f:
            
                reader = csv.reader(alrt_f)
                for row in reader:
                    i+=1
                    row_dict=dict(zip(snrt_frmt,row))
                    row_dict['timestamp']=time_to_ts(row_dict['timestamp'])
                    
                    pip_mtc={'$match': { '$and': [{'id_orig_h':row_dict['src']},
                                                  {'id_orig_p':int(row_dict['srcport'])},
                                                  {'id_resp_h':row_dict['dst']},
                                                  {'id_resp_p':int(row_dict['dstport'])}
                                                 ]  
                                       }
                            }
 
                    pip_add_flds={ '$addFields': { 'time_rt':
                                                    { '$or':[
                                                        { '$eq': ['$ts',row_dict['timestamp']]},
                                                        { '$and' : [
                                                                      { '$gt': [  {'$add': ['$ts', '$duration']},row_dict['timestamp'] ]},
                                                                      { '$lt':['$ts',row_dict['timestamp']] }
                                                                   ] 
                                                        }
                                                            ]  
                                                    }
                                                 }
                                 }
                    pip_mtc2= {'$match':{'time_rt':bool(True) }}
                    
                    pipeline = [ pip_mtc,pip_add_flds,pip_mtc2    ]
                    t_docs=collection_pcap.aggregate(pipeline)
                    Pdb().set_trace()
                    cursorlist = [c for c in t_docs]
                    len_t_docs= len(cursorlist)
                    if len_t_docs==0:
                        msg='snort alert fond no match: collection: '+collection_pcap+': directory= '+pcap_dir+': i= '+str(i)
                        myLogger.error(slp_msg)
                        exit
                    else:                         
                        for doc in cursorlist:
                            doc.keys()
                            if 'attack' not in doc.keys():
                                collection_pcap.update_one({'_id':doc['_id']},{'$set':
                                                                        {'attack':{
                                                                            'sig_id':row_dict['sig_id'],
                                                                            'sig_rev':row_dict['sig_rev'],
                                                                            'msg':row_dict['msg']
                                                                                  }
                                                                         }
                                                                      }
                                                 )
                                print(doc)
                                break
                            else:
                                continue
                            
                
                
                break
    
                
                if i-old_i>2000:
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
#    
    
    
    
    



    
    
        
    


main()



# In[ ]:


c

