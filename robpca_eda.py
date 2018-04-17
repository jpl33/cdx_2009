# -*- coding: utf-8 -*-
import pandas as pd
import math
import numpy as np
import scipy as sci

import json
import pymongo

import rpy2
from rpy2.robjects.packages import importr
import rpy2.robjects.numpy2ri

import itertools
import timeit

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
        if isinstance(obj, bool):
            return str(obj).lower()
        return json.JSONEncoder.default(self, obj)

def json_bool(obj):
    if isinstance(obj, bool):
            return str(obj).lower()
    if isinstance(obj, np.bool_):
            return str(obj).lower()
    return obj



pcap_dirs= ['maccdc2012_00001','maccdc2012_00002']#,'maccdc2012_00003','maccdc2012_00004']

client = pymongo.MongoClient('localhost')
db = client['local']

collection_bins= get_db()['bins']
time_interval=180



def unset_vars():
    collection_pcap.update_many({'bin':{'$exists':True}},{'$unset':{'orig_pkts_intr':'','mcd':'','bin':''}},upsert=False)



def which_feature_SD(df_row,pca_cov):
    numer2=pca_cov.dot(df_row.T)
    feat_list_x=list()
    for n in range(0,numer2.shape[1]):
        feat_list_i=list()
        for ni in range(0,numer2.shape[0]):
            feat_list_i.append(numer2[ni][n]**2/pca_cov[ni][ni] )
        feat_list_x.append(df_row.columns[feat_list_i.index(max(feat_list_i))])
    return feat_list_x


def which_feature_OD(df_row):
    feat_list_x=list()
    for n in range(0,df_row.shape[0]):
        feat_list_i=list(df_row.iloc[n])
        feat_list_x.append(df_row.columns[feat_list_i.index(max(feat_list_i))])
    return feat_list_x

def jsd(df,mcd):
    dff=pd.concat([df,mcd],axis=1)
    dff.columns=['df','mcd']    
    dff['m']=dff.sum(axis=1)/2
    dff['kl_df']=dff.df*np.log(dff.df/dff.m)
    dff['kl_mcd']=dff.mcd*np.log(dff.mcd/dff.m)
    dff['jsd']=dff.loc[:,'kl_df':'kl_mcd'].sum(axis=1)/2
    dff.fillna(0,inplace=True)
    return dff.jsd

#intervals=round(finish/interval_size)
df_eda=pd.DataFrame()

jdf_feature_cols2=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_pkts_intr','cumultv_pkt_count','orig_pkts_size','serv_freq','history_freq','conn_state_freq']

for pp in pcap_dirs:

    collection_pcap = get_db()[pp+'_conn']
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
    df_eda_cols=['collection','bin','count','attack_bool_count','mcd2','mcd2_attack_pcnt','SD_anomaly','SD_anomaly_attacks_pcnt','SD_anomaly_attacks_TP','SD2_anomaly','SD2_anomaly_attacks_pcnt','SD2_anomaly_attacks_TP','OD_anomaly','OD_anomaly_attacks_pcnt','OD_anomaly_attacks_TP','OD2_anomaly','OD2_anomaly_attacks_pcnt','OD2_anomaly_attacks_TP']
    
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
        df_s1=pd.Series([pp,
                            index,
                            df_cnt,
                            df.loc[df.attack_bool==True].shape[0],
                            df.loc[df.mcd2=='true'].shape[0],
                            df.loc[(df.mcd2=='true') & (df.attack_bool==True)].shape[0]/df.loc[df.attack_bool==True].shape[0],
                            df.loc[df.SD_anomaly=='true'].shape[0],
                            df.loc[(df.SD_anomaly=='true') & (df.attack_bool==True)].shape[0]/df.loc[df.attack_bool==True].shape[0],
                            df.loc[(df.SD_anomaly=='true') & (df.attack_bool==True)].shape[0]/df.loc[df.SD_anomaly=='true'].shape[0],
                            df.loc[df.SD2_anomaly=='true'].shape[0],
                            df.loc[(df.SD2_anomaly=='true') & (df.attack_bool==True)].shape[0]/df.loc[df.attack_bool==True].shape[0],
                            df.loc[(df.SD2_anomaly=='true') & (df.attack_bool==True)].shape[0]/df.loc[df.SD2_anomaly=='true'].shape[0],
                            df.loc[df.OD_anomaly=='true'].shape[0],
                            df.loc[(df.OD_anomaly=='true') & (df.attack_bool==True)].shape[0]/df.loc[df.attack_bool==True].shape[0],
                            df.loc[(df.OD_anomaly=='true') & (df.attack_bool==True)].shape[0]/df.loc[df.OD_anomaly=='true'].shape[0],
                            df.loc[df.OD2_anomaly=='true'].shape[0],
                            df.loc[(df.OD2_anomaly=='true') & (df.attack_bool==True)].shape[0]/df.loc[df.attack_bool==True].shape[0],
                            df.loc[(df.OD2_anomaly=='true') & (df.attack_bool==True)].shape[0]/df.loc[df.OD2_anomaly=='true'].shape[0],
                            ])
        df_r1=pd.DataFrame(df_s1).T
        df_r1.columns=df_eda_cols
        df_eda=df_eda.append(df_r1)
        first_ts+=time_interval

#df_eda.iloc[:,1:]=df_eda.iloc[:,1:].astype(float)
for cc in df_eda.iloc[:,1:]: df_eda[cc]=df_eda[cc].astype(float)
desc_list=[df_eda[cc].describe() for cc in df_eda.iloc[:,1:]]
mean_list=[mm['mean'] for mm in desc_list]
std_list=[mm['std'] for mm in desc_list]

for dd in [mean_list,std_list]:
    df_dd=pd.DataFrame(pd.Series(dd))
    df_dd=df_dd.T
    df_dd.columns=df_eda_cols[1:]
    df_eda.append(df_dd)
    
df_eda.to_csv("df_eda.csv")