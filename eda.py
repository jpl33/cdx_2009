# -*- coding: utf-8 -*-
import pandas as pd

import numpy as np
import json
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
import matplotlib.pyplot as plt
 
import seaborn as sns; sns.set(style="ticks", color_codes=True)
mongo_fields={"id.orig_h":"id_orig_h","id.orig_p":"id_orig_p","id.resp_h":"id_resp_h","id.resp_p":"id_resp_p"}

def get_db():
    return db

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'to_json'):
            return obj.to_json(orient='records')
        return json.JSONEncoder.default(self, obj)
    
#home_dir='D:\\personal\\msc\\maccdc_2012\\'
pcap_dir= 'maccdc2012_00000'
i=0
inter=0
client = pymongo.MongoClient('localhost')
db = client['local']
collection_pcap = get_db()[pcap_dir+'_conn']
finish=collection_pcap.count()
interval_size=100
intervals=10#round(finish/interval_size)
remainder=finish%interval_size
df_collection = {}
for index in range(intervals):
    time.sleep(30)
    doc_t=collection_pcap.find(sort=[('_Id',1)],limit=interval_size,skip=index*interval_size)
    df =  pd.DataFrame(list(doc_t))    
    s1=df[['duration','orig_ip_bytes','resp_ip_bytes','orig_pkts','resp_pkts']].describe()
    sum_t=pd.DataFrame(s1)
    mdd=df[['duration','orig_ip_bytes','resp_ip_bytes','orig_pkts','resp_pkts']].median()
    sum_t=pd.concat([sum_t,pd.DataFrame(mdd).T])
    sum_t=sum_t.rename(index={0:'median'})
    df_collection[index]=sum_t


with open('result.json', 'w') as fp:
    json.dump(df_collection, fp, cls=JSONEncoder)

#json.load(open('result.json')
###You will get a dictionary with your dataframes. You can load them using

#pd.read_json(json.load(open('result.json'))['1'])

#dfc2['age'].hist(by=dfc2['vote'])
g = sns.pairplot(df)
