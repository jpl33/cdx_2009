
# coding: utf-8

# In[2]:


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

vuln_service={'http':0,'ftp':0,'dns':0,'dhcp':0,'sip':0,'ssh':0,'smb':0,'dce_rpc':0,'mysql':0,'snmp':0,'ssl':0}

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
df_feature_cols=['duration','orig_ip_bytes','resp_ip_bytes','orig_pkts','resp_pkts']


# In[ ]:


for index in range(intervals):
    from IPython.core.debugger import Pdb; 
    time.sleep(30)
    doc_t=collection_pcap.find(sort=[('_Id',1)],limit=interval_size,skip=index*interval_size)
    df =  pd.DataFrame(list(doc_t)) 
    df_cnt=df._id.count()
    srv_cnt= df['service'].value_counts()
    srv_dict={}
    srv_dfs={}
    for nm in srv_cnt:    
        srv_dict[srv_cnt[srv_cnt==nm].index[0]]=nm
        if nm/df_cnt>0.2:
            d1=df[df.service==srv_cnt[srv_cnt==nm].index[0]]
            srv_dfs[srv_cnt[srv_cnt==nm].index[0]]=d1[df_feature_cols]
        #print(nm)
        #print(srv_cnt[srv_cnt==nm].index[0])
    Pdb().set_trace()
    
    df_http=df[df.service=='http']
    s1=df[df_feature_cols].describe()
    sum_t=pd.DataFrame(s1)
    mdd=df[df_feature_cols].median()
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

