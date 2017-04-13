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


#with open(home_dir+pcap_dir +'ntlm.txt','r') as tsvin, open('new.csv', 'w') as csvout:
#    tsvin = csv.reader(tsvin, delimiter='\t')
#    csvout = csv.writer(csvout)
#    for line in itertools.islice(tsvin, skip, None):
#        li = str(line).strip()
#        print (li)
        
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

df=pd.read_json(home_dir+pcap_dir +'conn.json',orient= 'records',lines=True)

conn_data[0].keys()
query=[ntlm_data[0]['id.orig_h'],ntlm_data[0]['id.orig_p'],ntlm_data[0]['id.resp_h'],ntlm_data[0]['id.resp_p']]
df.columns
query2=df.columns
line1=df[(df['id.orig_h']==query[0]) & (df['id.orig_p']==query[1])]
'%.2f' % line1['ts']
 import datetime
print(
    datetime.datetime.fromtimestamp(
        float('%.2f'% line1['ts'])
    ).strftime('%Y-%m-%d %H:%M:%S.%f')
)
'ntlm' in str(line1['service'].values[0]).split(',')
#df = DataFrame.from_csv(home_dir+pcap_dir +'ntlm.txt', sep="\t")        

#    
#d = datetime.date(2015,1,5)
#
#unixtime = time.mktime(d.timetuple())

#file = sys.argv[1]
#colname = sys.argv[2]
#client = pymongo.MongoClient('localhost')
#db = client['nettitude']
#collection = db[colname]
#with open(file) as f:
#for line in f.readlines():
#collection.insert(json.loads(line))