# -*- coding: utf-8 -*-
"""
Created on Tue Jan 16 09:53:31 2018

@author: root
"""


# coding: utf-8

# In[2]:


# -*- coding: utf-8 -*-
import pandas as pd
import math
import numpy as np
import json
import pymongo
import sys
import os
import rpy2

#import csv
#import io
#import re
import itertools
import getopt
import logging
import time
import matplotlib.pyplot as plt
import seaborn as sns; sns.set(style="ticks", color_codes=True)

home_dir='D:\\personal\\msc\\maccdc_2012\\'


logFormt='%(asctime)s: %(filename)s: %(lineno)d: %(message)s'
fh=logging.FileHandler(filename=home_dir+'error.log')
fh.setLevel(logging.DEBUG)
frmt=logging.Formatter(fmt=logFormt)
fh.setFormatter(frmt)
myLogger = logging.getLogger('maccdc')
myLogger.setLevel(logging.DEBUG)
myLogger.addHandler(fh)


mongo_fields={"id.orig_h":"id_orig_h","id.orig_p":"id_orig_p","id.resp_h":"id_resp_h","id.resp_p":"id_resp_p"}

vuln_service={'http':0,'ftp':0,'dns':0,'dhcp':0,'sip':0,'ssh':0,'smb':0,'dce_rpc':0,'mysql':0,'snmp':0,'ssl':0}

collection_filters={'conn':[('ts',pymongo.ASCENDING)]}
conn_fields= [  'duration',    'orig_bytes', 'orig_pkts', 'resp_bytes', 
       'resp_pkts' ]


def get_db():
    return db

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'to_json'):
            return obj.to_json(orient='records')
        return json.JSONEncoder.default(self, obj)


pcap_dir= 'maccdc2012_00000'

client = pymongo.MongoClient('localhost')
db = client['local']
collection_pcap = get_db()[pcap_dir+'_conn']
collection_bins= get_db()['bins']
finish=collection_pcap.count()
time_interval=180
#intervals=round(finish/interval_size)
df_collection = {}
df_feature_cols=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','attack_bool']

#doc_t=collection_pcap.find(sort=[('_Id',1)],limit=interval_size,skip=index*interval_size)
# # find first timestamp
first_doc= collection_pcap.find(sort=[('ts',1)],limit=1)
# # we received a collection of ONE,but we only care about the first timestamp
for dd in first_doc: first_ts=dd['ts']
# # find last timestamp
last_doc= collection_pcap.find(sort=[('ts',-1)],limit=1)
# # we received a collection of ONE,but we only care about the first timestamp
for dd in last_doc: last_ts=dd['ts']

intervals=math.ceil((last_ts-first_ts)/time_interval)

for index in range(intervals):
    
    
    # # find from the timestamp, up to the pre-set time interval size
    doc_tt=collection_pcap.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':first_ts+time_interval}}]})
    df =  pd.DataFrame(list(doc_tt)) 
    df_cnt=df.shape[0]
    from rpy2.robjects.packages import importr
    import rpy2.robjects.numpy2ri
    rpy2.robjects.numpy2ri.activate()
    rospca=importr("rospca")
    robust_base=importr("robustbase")
    df_clean=df[conn_fields]
    df_clean=df_clean.fillna(0)
    ## hard to believe but pandas does NOT have a normalizing function
    #df_norm=(df_clean-df_clean.mean())/df_clean.std()
    df_mat=df_clean.as_matrix()
    rpca=rospca.robpca(x=df_mat,mcd=True)
    mcd=robust_base.covMcd(df_mat,cor = True, alpha=0.75)
    loadings=np.array(rpca[0])
    mcd_cov=np.array(mcd[3])
    mcd_cor=np.array(mcd[6])
    H0=np.array(rpca[5])
    df_clean["mcd"]=0
    #df_clean[df_clean["mcd"]]
    for hh in H0:
        df_clean.loc[hh-1,"mcd"]=1
    df_clean["attack_bool"]=True
    df_clean["attack_bool"][df["attack_bool"]==False]=False
    fig=plt.figure(figsize=(14,10))
    #fig, axes = plt.subplots(1, 1, sharex=True, sharey=True)
    colors = {0: 'red', 1: 'aqua'}
    markers={1:"o",0:"p"}
   
    groups = df_clean.groupby('attack_bool')

    fig, axes = plt.subplots(1, 1, sharex=True, sharey=True,figsize=(14,10))

    for name, group in groups:   
            if name==False:
                axes.scatter(x=group["orig_bytes"],y=group["resp_bytes"],c=group.mcd.map(colors),marker='o',label='no attack',vmin=0, vmax=4)
                #plt.show()
            else:
                axes.scatter(x=group["orig_bytes"],y=group["resp_bytes"],c=group.mcd.map(colors),marker='p',label='attack',vmin=0, vmax=4)                       
                plt.show()
    #axes.scatter(x=df_clean["orig_bytes"],y=df_clean["resp_bytes"],c=df_clean.mcd.map(colors))
    #ax.legend()
    plt.show()
    fig.savefig('plot_mcd.png',bbox_inches='tight')  
    print("finished pca")
    