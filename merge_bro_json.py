# -*- coding: utf-8 -*-
"""
Created on Thu Mar 30 14:20:31 2017

@author: root
"""

#!/usr/bin/python
import json
import pandas as pd
from pandas import DataFrame
import pymongo
import jsonmerge
import sys
import csv
import io
import re
import itertools


home_dir='D:\\personal\\msc\\maccdc_2012\\'
pcap_dir= 'maccdc2012_00003\\'


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

def mongo_json(mydict):
    for key,value in mydict.items():
           if key in mongo_fields:
               mydict[mongo_fields[key]]= mydict.pop(key)
        
ntlm_data = []
with open(home_dir+pcap_dir +'ntlm.json','r') as ntlm_f:
    for line in itertools.islice(ntlm_f, 0,6):
        ntlm_data.append(json.loads(line))
dns_data=[]
with open(home_dir+pcap_dir +'dns.json','r') as dns_f:
    for line in itertools.islice(dns_f, 0,2):
        dns_data.append(json.loads(line))
        
conn_data=[]
with open(home_dir+pcap_dir +'conn.json','r') as conn_f:
    for line in itertools.islice(conn_f, 0,500):
        conn_data.append(json.loads(line))


conn_data[0].keys()
query=[ntlm_data[0]['id.orig_h'],ntlm_data[0]['id.orig_p'],ntlm_data[0]['id.resp_h'],ntlm_data[0]['id.resp_p']]

nt_json=[]
import ijson
#prs1=list(ijson.parse(fconn))
fconn = open(home_dir+pcap_dir +'conn2.json', 'rb')

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

#df = DataFrame.from_csv(home_dir+pcap_dir +'ntlm.txt', sep="\t")        
#df=pd.read_json(home_dir+pcap_dir +'conn.json',orient= 'records',lines=True)
#df.columns
#query2=df.columns
#line1=df[(df['id.orig_h']==query[0]) & (df['id.orig_p']==query[1])]
#'%.2f' % line1['ts']
#'ntlm' in str(line1['service'].values[0]).split(',')

#import datetime
#print(
#    datetime.datetime.fromtimestamp(
#        float('%.2f'% line1['ts'])
#    ).strftime('%Y-%m-%d %H:%M:%S.%f')
#)
#    
#d = datetime.date(2015,1,5)

#unixtime = time.mktime(d.timetuple())

#file = sys.argv[1]
#colname = sys.argv[2]
client = pymongo.MongoClient('localhost')
db = client['local']
collection = db['pcap03']
conn_f.close()
with open(home_dir+pcap_dir +'conn.json','r') as conn_f:
    #for line in itertools.islice(conn_f, 0,5):
    for line in conn_f.readlines():
       jsndict=json.loads(line)
       mongo_json(jsndict)
       collection.insert(jsndict)