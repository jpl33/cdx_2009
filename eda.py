
# coding: utf-8



# -*- coding: utf-8 -*-
import pandas as pd
import math
import numpy as np
import scipy as sci
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


def get_db():
    return db

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'to_json'):
            return obj.to_json(orient='records')
        return json.JSONEncoder.default(self, obj)

def  set_collections_index(prefix):
     col_lst=get_db().collection_names() 
     for col in col_lst:
         if col.startswith(prefix):
             get_db()[col].create_index(collection_filters['conn'])

def  base_conn_stats(df):
     s1=df[df_feature_cols2].describe()
     sum_t=pd.DataFrame(s1)
     dcc=df[df['attack_bool']==True]
     dcc=dcc.shape[0]  
     sum_t.loc['count','attack_bool']=dcc
     return sum_t
    
#home_dir='D:\\personal\\msc\\maccdc_2012\\'
pcap_dir= 'maccdc2012_00002'

client = pymongo.MongoClient('localhost')
db = client['local']
collection_pcap = get_db()[pcap_dir+'_conn']
collection_bins= get_db()['bins']
finish=collection_pcap.count()
time_interval=180
#intervals=round(finish/interval_size)
df_collection = {}

df_feature_cols2=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_pkts_intr','cumultv_pkt_count','orig_pkts_size','serv_freq','history_freq','conn_state_freq','serv_jsd','history_jsd','conn_state_jsd']


#df_feature_cols2=['attack_bool','duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_pkts_intr','cumultv_pkt_count','orig_pkts_size','serv_freq','history_freq','conn_state_freq']

# In[ ]:
from IPython.core.debugger import Pdb; 
    #time.sleep(30)
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
        doc_tt=collection_pcap.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':first_ts+time_interval}},{'orig_bytes':{'$gt':0}}]})
    df =  pd.DataFrame(list(doc_tt)) 
    df_cnt=df._id.count()
    
    # # get the count of different 'service' flags 
    srv_cnt= df['service'].value_counts()
    srv_dict={}
    srv_dfs={}
    
    
#    df['orig_pkts_intr']=df.orig_pkts/df.duration
#    df['cumultv_pkt_count']=0
    # # get all flows that have tcp-level byte exchange ("orig_bytes")
    df2=df.copy()
    sum_t=base_conn_stats(df2)
    df_dict=json.loads(sum_t.to_json())
    df_jsn=dict()
    df_attk=dict()
    df_jsn['conn_bin']=df_dict
    df_atk_cn=df2[df2.attack_bool==True]
    df_atk_cn_jsn=base_conn_stats(df_atk_cn)
    df_attk['conn_bin']=json.loads(df_atk_cn_jsn.to_json())



    
#    msg='start looking for bad flows. Line217'
#    myLogger.error(msg)
#    
#    df2.ts=df2.ts.round()
#    gb=df2.groupby(['id_orig_h','id_resp_h'])
#    ggtsdf=list()
#    gdict=gb.groups
#    # # iterate over orig-resp pairs, aggregate flows per second, and get the median of the origin pkts sent
#    for ss in gb.groups:
#        gtemp=gb.get_group(ss)
#        df3=gtemp.groupby(['ts']).sum()
#        gtsdf=df3.orig_pkts.median()
#        # # ggtsdf is list of all pairs origin_pkts/second medians
#        ggtsdf.append(gtsdf)
#        # # set 'cumultv_pkt_count' for all indexes that belong to orig-resp pair
#        df2.loc[gdict[ss].values,df2.columns.get_loc('cumultv_pkt_count')]=gtsdf
#        # # set 'cumultv_pkt_count' for all indexes that belong to orig-resp pair
#        df.loc[gdict[ss].values,df.columns.get_loc('cumultv_pkt_count')]=gtsdf
#    
#    # # series of orig_pkts/sec medians with orig-resp pairs as index    
#    op_ser=pd.Series(ggtsdf,index=gdict.keys()) 
#    iqr=sci.stats.iqr(op_ser)
#    q3=op_ser.quantile(0.75)
#    # # upper threshold for orig-dest cumulative orig_pkts/sec
#    cum_pkt_sec_th=q3+1.5*iqr
#    op_df=pd.DataFrame(op_ser)
#    
#    # # array of all orig-dest orig_pkts/sec medians HIGHER tha the threshold
#    armean=op_ser.loc[op_ser>(cum_pkt_sec_th)].index
#    for sd in armean:
#        gtemp2=gb.get_group(sd)
#        # # just how many flows of this orig-resp pair are there in this bin
#        op_df.loc[sd,'num']=gtemp2.shape[0]
#    
#    # # sort the dataframe for the highest number of flows, NOT the highest orig_pkts/sec. we want the pair that has the most influence on our data
#    op_df=op_df.sort_values(by='num', ascending = False)
#    # # total number of flows of pairs with orig_pkts/sec higher than the threshold
#    num_sum=op_df.num.sum()
#    outly_flws=0
#    outly_pairs=list()
#    for nn in op_df.index:
#        outly_flws+=float(op_df.loc[op_df.index==nn].num)
#        outly_pairs.append(nn)
#        # # are the flows of the rest of the pairs less than 25% of available flows? if so, they won't affect the MCD.
#        outly_th=0.25*(df_cnt-outly_flws)
#        if num_sum-outly_flws<outly_th:
#            break
#    msg='finish looking for bad flows. Line264: directory= '+pcap_dir+':index='+str(index)
#    myLogger.error(msg)



    
    for nm in srv_cnt:
###     
###     if the service connections are more than 20% of all connections in the current sample
###     slice the current sample according to service  
        if nm>80:
            # # get the service name
            srv_nm=srv_cnt[srv_cnt==nm].index[0]
            
        # # get the service names if it's a compound service
            srv_lst=srv_nm.split(',')
            # # only get service name if it's in our service list
            srv_lstrd=[ssr for ssr in srv_lst if ssr in vuln_service.keys()]

            for ssrv in srv_lstrd: 
                
                # # search the service collection for number of REAL entries
                try:
                    coll_srv=get_db()[pcap_dir+'_'+ssrv]
                
                except Exception as e:
                    error=str(e)+':service name='+str(ssrv)+':collection_conn='+str(pcap_dir+'_conn')+':index='+str(i)
                    myLogger.error(error)
                    continue
                d1=df[(df.service==srv_nm)&(df.orig_bytes>0)]
###            the service name is the index of 'srv_cnt', 
###     here we are actually creating a dictionary of services
###        and their counts in the  current sample - 'srv_dict'
        # # create new service data Frame
                srv_dfs[ssrv]=d1[df_feature_cols2]
                sl=srv_dfs[ssrv].describe()
                st=pd.DataFrame(sl)
                dcc=d1[d1['attack_bool']==True]
                dcc=dcc.shape[0]  
                sum_t.loc['count','attack_bool']=dcc
                srv_atk=srv_dfs[ssrv][srv_dfs[ssrv].attack_bool==True]
                srv_dfs[ssrv]=sum_t.to_json()
                srv_atk_jsn=base_conn_stats(srv_atk)
                df_attk[ssrv]=json.loads(srv_atk_jsn.to_json())
                if index==intervals-1:
                    srv_doc_tt=coll_srv.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':last_ts}}]})
                else:
                    srv_doc_tt=coll_srv.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':first_ts+time_interval}}]})
                coll_srv_df=pd.DataFrame(list(srv_doc_tt))
                coll_srv_count=coll_srv_df.shape[0]
                srv_dict[ssrv]=int(coll_srv_count)
                
                
        
    for dd in srv_dfs.keys():
        ddjn=json.loads(srv_dfs[dd])
        df_jsn[dd]=ddjn
    
    
    df_jsn['first_ts']=first_ts
    if index==intervals-1:
        df_jsn['last_ts']=last_ts
    else:
        df_jsn['last_ts']=first_ts+time_interval
    df_jsn['pcap_dir']=pcap_dir
    # #  increment the timestamp
    first_ts=first_ts+time_interval
    df_jsn['real']=srv_dict
    df_jsn['index']=index
    df_jsn['attack']=df_attk
    df_jsn['outlying_pairs']=json.dumps(outly_pairs)
    
    try:
        collection_bins.insert_one(df_jsn)
        #collection_bins.insert_one(ddjn2)

    except Exception as e:
            error=str(e)+':doc='+str(df_jsn)+':index='+str(index)
            myLogger.error(error)
            exit





#json.load(open('result.json')
###You will get a dictionary with your dataframes. You can load them using

#pd.read_json(json.load(open('result.json'))['1'])

#dfc2['age'].hist(by=dfc2['vote'])
#g = sns.pairplot(df)

