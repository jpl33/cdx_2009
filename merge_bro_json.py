# -*- coding: utf-8 -*-
"""
Created on Thu Mar 30 14:20:31 2017

@author: root
"""

#!/usr/bin/python
import json
import pandas
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
        
data = []
with open(home_dir+pcap_dir +'ntlm.log','r') as f:
    for line in itertools.islice(f, 0,3):
        data.append(json.loads(line))
#from pandas import DataFrame
#df = DataFrame.from_csv(home_dir+pcap_dir +'ntlm.txt', sep="\t")        



#file = sys.argv[1]
#colname = sys.argv[2]
#client = pymongo.MongoClient('localhost')
#db = client['nettitude']
#collection = db[colname]
#with open(file) as f:
#for line in f.readlines():
#collection.insert(json.loads(line))