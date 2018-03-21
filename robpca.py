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
import scipy as sci
import json
import pymongo
import sys
import os
import rpy2
from rpy2.robjects.packages import importr
import rpy2.robjects.numpy2ri
#import csv
#import io
#import re
import itertools
import timeit
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



def   time_to_ts(row_ts):  
      strd=row_ts[:-2]
      dt=datetime.datetime.strptime(strd,'%m/%d/%y-%H:%M:%S.%f')
      snrt_ts = dt.timestamp()
      snrt_ts=snrt_ts+7200
      return snrt_ts



def get_db():
    return db

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'to_json'):
            return obj.to_json(orient='records')
        return json.JSONEncoder.default(self, obj)


pcap_dir= 'maccdc2012_00001'

client = pymongo.MongoClient('localhost')
db = client['local']
collection_pcap = get_db()[pcap_dir+'_conn']
collection_bins= get_db()['bins']
finish=collection_pcap.count()
time_interval=180



def unset_vars():
    collection_pcap.update_many({'bin':{'$exists':True}},{'$unset':{'orig_pkts_intr':'','mcd':'','bin':''}},upsert=False)

def robust_f_params(n,p,h):
    #h=(n+p+1)/2
    a=1-h
    qa=chi2.isf(a,df=p)
    d=chi2.cdf(qa,p+2)
    ca=h/(d)
    c2=-d/2
    c3=-(chi2.cdf(qa,p+4))/2
    c4=3*c3
    b1=ca*(c3-c4)/h
    b2=.5+(ca/h)*(c3-(qa/p)*(c2+h/2))
    v1=(p+2)*b2*(2*b1-p*b2)

#intervals=round(finish/interval_size)
df_collection = {}
df_feature_cols=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_pkts_intr','cumultv_pkt_count','orig_pkts_size','serv_freq','history_freq','conn_state_freq']

#doc_t=collection_pcap.find(sort=[('_Id',1)],limit=interval_size,skip=index*interval_size)
# # find first timestamp
first_doc= collection_pcap.find(sort=[('ts',1)],limit=1)
# # we received a collection of ONE,but we only care about the first timestamp
for dd in first_doc: first_ts=dd['ts']
# # find last timestamp
last_doc= collection_pcap.find(sort=[('ts',-1)],limit=1)
# # we received a collection of ONE,but we only care about the first timestamp
for dd in last_doc: last_ts=dd['ts']

intervals=math.floor((last_ts-first_ts)/time_interval)

for index in range(intervals):
    
    if index==intervals-1:
        doc_tt=collection_pcap.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lte':last_ts}},{'orig_bytes':{'$gt':0}}]})
    else:
        # # find from the timestamp, up to the pre-set time interval size
        # #  find only the flows whose 'orig_bytes'>0 => meaning they have some TCP-level activity
        doc_tt=collection_pcap.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':first_ts+time_interval}},{'orig_bytes':{'$gt':0}}]})

    df =  pd.DataFrame(list(doc_tt)) 
    # # number of flows in bin
    df_cnt=df.shape[0]
    # # origin_pkts interval per flow
    df['orig_pkts_intr']=df.orig_pkts/df.duration
    
    df['orig_pkts_size']=df.orig_bytes/df.orig_pkts
    
    serv_freq=df.service.value_counts()/df_cnt
    df['serv_freq']=0
    for idd in serv_freq.index.values:
        df.loc[df.service==idd,'serv_freq']= serv_freq.loc[idd]       
    
    history_freq=df.history.value_counts()/df_cnt
    df['history_freq']=0
    for idd in history_freq.index.values:
        df.loc[df.history==idd,'history_freq']= history_freq.loc[idd]    
    
    conn_state_freq=df.conn_state.value_counts()/df_cnt
    df['conn_state_freq']=0
    for idd in conn_state_freq.index.values:
        df.loc[df.conn_state==idd,'conn_state_freq']= conn_state_freq.loc[idd]    
    
    
    
    df2=df.copy()
    df2.ts=df2.ts.round()
    # # cumulative origin pkts per second for  orig-resp pairs
    df2['cumultv_pkt_count']=0
    gb=df2.groupby(['id_orig_h','id_resp_h'])
    ggtsdf=list()
    gdict=gb.groups
    # # iterate over orig-resp pairs, aggregate flows per second, and get the median of the origin pkts sent
    for ss in gb.groups:
        gtemp=gb.get_group(ss)
        df3=gtemp.groupby(['ts']).sum()
        gtsdf=df3.orig_pkts.median()
        # # ggtsdf is list of all pairs origin_pkts/second medians
        ggtsdf.append(gtsdf)
        # # set 'cumultv_pkt_count' for all indexes that belong to orig-resp pair
        df2.iloc[gdict[ss].values,df2.columns.get_loc('cumultv_pkt_count')]=gtsdf
        
    # # series of orig_pkts/sec medians with orig-resp pairs as index    
    op_ser=pd.Series(ggtsdf,index=gdict.keys()) 
    iqr=sci.stats.iqr(op_ser)
    q3=op_ser.quantile(0.75)
    # # upper threshold for orig-dest cumulative orig_pkts/sec
    cum_pkt_sec_th=q3+1.5*iqr
    op_df=pd.DataFrame(op_ser)
    
    # # array of all orig-dest orig_pkts/sec medians HIGHER tha the threshold
    armean=op_ser.loc[op_ser>(cum_pkt_sec_th)].index
    for sd in armean:
        gtemp2=gb.get_group(sd)
        # # just how many flows of this orig-resp pair are there in this bin
        op_df.loc[sd,'num']=gtemp2.shape[0]
    
    # # sort the dataframe for the highest number of flows, NOT the highest orig_pkts/sec. we want the pair that has the most influence on our data
    op_df=op_df.sort_values(by='num', ascending = False)
    # # total number of flows of pairs with orig_pkts/sec higher than the threshold
    num_sum=op_df.num.sum()
    outly_flws=0
    outly_pairs=list()
    for nn in op_df.num:
        outly_flws+=nn
        outly_pairs.append(op_df.loc[op_df.num==nn].index[0])
        # # are the flows of the rest of the pairs less than 25% of available flows? if so, they won't affect the MCD.
        outly_th=0.25*(df_cnt-outly_flws)
        if num_sum-outly_flws<outly_th:
            break
    rpy2.robjects.numpy2ri.activate()
    rospca=importr("rospca")
    robust_base=importr("robustbase")
    for ppn in outly_pairs:
        # # dump all flows belonging to orig-resp pairs in outly_pairs from the overall bin flows
        df_clean=df2[~df2.index.isin(gdict[ppn].values)]
        df_clean=df_clean[df_feature_cols]
        df_clean=df_clean.fillna(0)
    
    df_mat=df_clean.as_matrix()
    rpca=rospca.robpca(x=df_mat,mcd=True)
    mcd=robust_base.covMcd(df_mat,cor = True, alpha=0.75)
    loadings=np.array(rpca[0])
    mcd_cov=np.array(mcd[3])
    mcd_cor=np.array(mcd[6])
    H0=np.array(rpca[5])
    H1=np.array(rpca[6])
    dfh_h0=df.iloc[H0-1]
    df_clean["mcd"]=False
    #df_clean[df_clean["mcd"]]
    for hh in H0:
        df_clean.iloc[hh-1,df_clean.columns.get_loc('mcd')]=True
    
    bin_lst=list(df._id)
    mcd_lst=list(df2.loc[df_clean.loc[df_clean.mcd==True].index.values,'_id'])
    
    time_bulk=timeit.default_timer()
    bulk=collection_pcap.initialize_unordered_bulk_op()
    for idd in bin_lst:
        bulk.find({'_id':idd}).update_one({'$set':{'orig_pkts_intr':df.loc[df._id==idd,'orig_pkts_intr'].values[0]
                                                    ,'orig_pkts_size':df.loc[df._id==idd,'orig_pkts_size'].values[0]
                                                    ,'serv_freq':df.loc[df._id==idd,'serv_freq'].values[0]
                                                    ,'history_freq':df.loc[df._id==idd,'history_freq'].values[0]
                                                    ,'conn_state_freq':df.loc[df._id==idd,'conn_state_freq'].values[0]}})
    bulk.execute()   
    elapsed_bulk=timeit.default_timer()-time_bulk
    

    
   
    
    collection_pcap.update_many({'_id': {'$in': bin_lst}},{'$set':{'mcd':False}})
    collection_pcap.update_many({'_id': {'$in': bin_lst}},{'$set':{'bin':index}})
    collection_pcap.update_many({'_id': {'$in': mcd_lst}},{'$set':{'mcd':True}})
    
    df_mcd=pd.DataFrame(mcd_cor)
    df_mcd.columns=df_clean.columns[:-1]
    mcd_js=df_mcd.to_json()
    mcd_dict=json.loads(mcd_js)
    llp=json.dumps(outly_pairs)
    
    collection_bins.update_one({'pcap_dir':pcap_dir,'index':index},{'$set':{'mcd_cor':mcd_dict,'outlying_pairs':llp}},upsert=False)
    
    
#    mcd_df2=pd.read_json(json.dumps(mcd_dict))
#    llp=json.loads(llp)



#    collection_pcap.update_many({'orig_pkts_intr':{'$exists':True}},{'$unset':{'orig_pkts_intr':''}},upsert=False)
#    
#    time_single=timeit.default_timer()
#    doc_idd=collection_pcap.find({'_id':{'$in':bin_lst}})
#    for idd in doc_idd:
#        collection_pcap.update_one({'_id':idd['_id']},{'$set':{'orig_pkts_intr':df.loc[df._id==idd['_id'],'orig_pkts_intr'].values[0]}})
#    elapsed_single=timeit.default_timer()-time_single    
#    gb=df.groupby(['id_orig_h','id_resp_h'])
#    ggtsdf=list()
#    gdict=gb.groups
#    for ss in gb.groups:
#        gtemp=gb.get_group(ss)
#        if gtemp.ts.count()<2:
#            ggtsdf.append(0)
#            df.iloc[gdict[ss].values,34]=0
#            continue
#        gtsdf=gtemp.ts.diff()
#        gtsdfmd=gtsdf.median()
#        ggtsdf.append(gtsdfmd)
#        df.iloc[gdict[ss].values,34]=gtsdfmd
#    ts_dict=dict(zip(gdict.keys(),ggtsdf)) 