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




client = pymongo.MongoClient('localhost')
db = client['local']

collection_bins= get_db()['bins']
time_interval=180



def unset_vars():
    service_collection.update_many({'bin':{'$exists':True}},{'$unset':{'orig_pkts_intr':'','mcd':'','bin':''}},upsert=False)



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

def normalise_gaussian(sdx):                
        sdx_mean=sdx.mean()
        sdx_std=sdx.std()
        z=(sdx-sdx_mean)/(sdx_std*math.sqrt(2) )
        raw_norm_gauss=sci.special.erf(z)
        norm_gauss=pd.Series(raw_norm_gauss)
        norm_gauss.loc[norm_gauss<0]=0
        return norm_gauss

def normalise_gamma(sdx):                
        sdx_mean=sdx.mean()
        sdx_std=sdx.std()
        k=(sdx_mean**2)/(sdx_std**2)
        theta=sdx_std/sdx_mean*2
        cdf_gamma_x=sci.special.gammainc(k,sdx.values/theta)
        cdf_gamma_mu=sci.special.gammainc(k,sdx_mean/theta)
        cdf_gamma_mu_arr=np.repeat(cdf_gamma_mu,sdx.shape[0])
        raw_norm_gamma=(  (cdf_gamma_x-cdf_gamma_mu_arr)/(1-cdf_gamma_mu)   )
        norm_gamma=pd.Series(raw_norm_gamma)
        norm_gamma.loc[norm_gamma<0]=0
        return norm_gamma

#intervals=round(finish/interval_size)
df_eda=pd.DataFrame()

jdf_feature_cols2=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_pkts_intr','cumultv_pkt_count','orig_pkts_size','serv_freq','history_freq','conn_state_freq']

services=['http','ftp','dns']#,'ssl',
pcap_dirs= ['maccdc2012_00003']#'maccdc2012_00001','maccdc2012_00002','maccdc2012_00004']


for srv in services:
    for pp in pcap_dirs:
        service_collection_name=pp+'_'+srv#+'_pp'
        conn_collection_name=pp+'_conn'#+'_pp'
        service_collection = get_db()[service_collection_name]
        conn_collection = get_db()[conn_collection_name]
        #doc_t=service_collection.find(sort=[('_Id',1)],limit=interval_size,skip=index*interval_size)
        # # find first timestamp
        first_doc= conn_collection.find(sort=[('ts',1)],limit=1)
        # # we received a collection of ONE,but we only care about the first timestamp
        for dd in first_doc: first_ts=dd['ts']
        # # find last timestamp
        last_doc= conn_collection.find(sort=[('ts',-1)],limit=1)
        # # we received a collection of ONE,but we only care about the first timestamp
        for dd in last_doc: last_ts=dd['ts']
        
        intervals=math.floor((last_ts-first_ts)/time_interval)
        if intervals<1:
            continue
        df_eda_cols=['collection','bin','count','attack_bool_count','mcd','mcd_attack_pcnt','SD_anomaly','SD_anomaly_recall','SD_anomaly_percision','OD_anomaly','OD_anomaly_recall','OD_anomaly_percision','SD_F1','OD_F1']
        
        for index in range(intervals):
    
            if index==intervals-1:
                srv_doc_tt=service_collection.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lte':last_ts}}]})#,{'orig_bytes':{'$gt':0}}
                conn_doc_tt=conn_collection.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lte':last_ts}},{'$or':[{'orig_bytes':{'$gt':0}},{'service':srv}]}]})
            else:
                # # find from the timestamp, up to the pre-set time interval size
                # #  find only the flows whose 'orig_bytes'>0 => meaning they have some TCP-level activity
                srv_doc_tt=service_collection.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':first_ts+time_interval}}]})#,{'orig_bytes':{'$gt':0}}
                conn_doc_tt=conn_collection.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':first_ts+time_interval}},{'$or':[{'orig_bytes':{'$gt':0}},{'service':srv}]}]})
          
            srv_df =  pd.DataFrame(list(srv_doc_tt)) 
            conn_df =  pd.DataFrame(list(conn_doc_tt)) 
            # # number of flows in bin
            srv_df_cnt=srv_df.shape[0]
            conn_df_cnt=conn_df.shape[0]
#            if df_cnt<100:
#                first_ts+=time_interval
#                continue
            #srv_SD_th=collection_bins.aggregate({'$merge':{'pcap_dir':pp,'bin':index}},{'$project':'http_SD_th'})
            if srv_df.loc[srv_df.SD_anomaly=='true'].shape[0]>0:
                srv_SD_precision=srv_df.loc[(srv_df.SD_anomaly=='true') & (srv_df.attack_bool==True)].shape[0]/srv_df.loc[srv_df.SD_anomaly=='true'].shape[0]
                srv_df['SD_norm']=normalise_gamma(srv_df.SD)
            else:
                srv_SD_precision=0
            
            if srv_df.loc[srv_df.OD_anomaly=='true'].shape[0]>0:
                srv_OD_precision=srv_df.loc[(srv_df.OD_anomaly=='true') & (srv_df.attack_bool==True)].shape[0]/srv_df.loc[srv_df.OD_anomaly=='true'].shape[0]
                srv_df['OD_norm']=normalise_gaussian(srv_df.OD)
            else:
                srv_OD_precision=0
  
            if conn_df.loc[conn_df.SD_anomaly=='true'].shape[0]>0:
                conn_SD_precision=conn_df.loc[(conn_df.SD_anomaly=='true') & (conn_df.attack_bool==True)].shape[0]/conn_df.loc[conn_df.SD_anomaly=='true'].shape[0]
                conn_df['SD_norm']=normalise_gamma(conn_df.SD)
            else:
                conn_SD_precision=0
            
            if conn_df.loc[conn_df.OD_anomaly=='true'].shape[0]>0:
                conn_OD_precision=conn_df.loc[(conn_df.OD_anomaly=='true') & (conn_df.attack_bool==True)].shape[0]/conn_df.loc[conn_df.OD_anomaly=='true'].shape[0]
                conn_df['OD_norm']=normalise_gaussian(conn_df.OD)
            else:
                conn_OD_precision=0


            if conn_df.loc[conn_df.attack_bool==True].shape[0]>0:
                conn_SD_recall=conn_df.loc[(conn_df.SD_anomaly=='true') & (conn_df.attack_bool==True)].shape[0]/conn_df.loc[conn_df.attack_bool==True].shape[0]
                conn_attacks=conn_df.loc[(conn_df.attack_bool==True)].shape[0]
                conn_OD_recall=conn_df.loc[(conn_df.OD_anomaly=='true') & (conn_df.attack_bool==True)].shape[0]/conn_df.loc[conn_df.attack_bool==True].shape[0]
            else:
                conn_SD_recall=0
                conn_attacks=0
                conn_OD_recall=0
                
            if srv_df.loc[srv_df.attack_bool==True].shape[0]>0:
                srv_SD_recall=srv_df.loc[(srv_df.SD_anomaly=='true') & (srv_df.attack_bool==True)].shape[0]/srv_df.loc[srv_df.attack_bool==True].shape[0]
                srv_attacks=srv_df.loc[(srv_df.attack_bool==True)].shape[0]
                OD_recall=srv_df.loc[(srv_df.OD_anomaly=='true') & (srv_df.attack_bool==True)].shape[0]/srv_df.loc[srv_df.attack_bool==True].shape[0]
            else:
                srv_SD_recall=0
                srv_attacks=0
                srv_OD_recall=0
                           
                
            sdd=pd.DataFrame()
            sdd['uid']=conn_df.uid 
            sdd['conn_attack']=conn_df.attack_bool
            sdd['conn_SD']=conn_df.SD
            sdd['conn_SD_norm']=conn_df.SD_norm
            sdd['conn_OD']=conn_df.OD
            sdd['conn_OD_norm']=conn_df.OD_norm
            sdd[srv+'_attacks']='false'
            sdd['service']='false'
            sdd[srv+'_SD']='false'
            sdd[srv+'_OD']='false'
            sdd[srv+'_SD_norm']='false'
            sdd[srv+'_OD_norm']='false'
            ll=[x if x in set(conn_df.uid) else 0 for x in srv_df.uid]
            ll=[l for l in ll if l!=0]
            for uu in ll:
                sdd.loc[sdd.uid==uu,srv+'_attacks']=json_bool(srv_df.loc[srv_df.uid==uu,'attack_bool'].values[0])
                sdd.loc[sdd.uid==uu,srv+'_SD']=srv_df.loc[srv_df.uid==uu,'SD'].values[0]
                sdd.loc[sdd.uid==uu,srv+'_SD_norm']=srv_df.loc[srv_df.uid==uu,'SD_norm'].values[0]
                sdd.loc[sdd.uid==uu,srv+'_OD']=srv_df.loc[srv_df.uid==uu,'OD'].values[0]
                sdd.loc[sdd.uid==uu,srv+'_OD_norm']=srv_df.loc[srv_df.uid==uu,'OD_norm'].values[0]
                sdd.loc[sdd.uid==uu,'service']=srv
                
            
            
            df_s1=pd.Series([service_collection_name,
                                index,
                                df_cnt,
                                df.loc[df.attack_bool==True].shape[0],
                                df.loc[df.mcd=='true'].shape[0],
                                mcd_attacks,
                                df.loc[df.SD_anomaly=='true'].shape[0],
                                SD_recall,
                                SD_precision,
                                df.loc[df.OD_anomaly=='true'].shape[0],
                                OD_recall,
                                OD_precision,
                                0,
                                0
                               ])
            df_r1=pd.DataFrame(df_s1).T
            df_r1.columns=df_eda_cols
            if SD_precision>0:
                SD_F1=2*df_r1.SD_anomaly_percision*df_r1.SD_anomaly_recall/(df_r1.SD_anomaly_percision+df_r1.SD_anomaly_recall)
            else:
                SD_F1=0
            if OD_recall>0:
                if OD_precision>0:
                    OD_F1=2*df_r1.OD_anomaly_percision*df_r1.OD_anomaly_recall/(df_r1.OD_anomaly_percision+df_r1.OD_anomaly_recall)
                else:
                    OD_F1=0
            else:
                OD_F1=0
            
            df_r1['SD_F1']=SD_F1
            df_r1['OD_F1']=OD_F1
            df_eda=df_eda.append(df_r1)
            first_ts+=time_interval
        df_eda_pp=df_eda.loc[df_eda.collection==pp]
        srv_lst=[x if x==service_collection_name else 0 for x in df_eda.collection ]
        df_eda_pp=df_eda.loc[df_eda.collection.isin(srv_lst)]
        anomal_attacks_SD=(df_eda_pp.SD_anomaly_recall*df_eda_pp.attack_bool_count).sum()
        attacks=df_eda_pp.attack_bool_count.sum()
        anomalies_SD=df_eda_pp.SD_anomaly.sum()
        anomal_attacks_OD=(df_eda_pp.OD_anomaly_recall*df_eda_pp.attack_bool_count).sum()
        anomalies_OD=df_eda_pp.OD_anomaly.sum()
        if attacks==0:
            recall_SD=0
            recall_OD=0
        else:
            recall_SD=anomal_attacks_SD/attacks
            recall_OD=anomal_attacks_OD/attacks
        if anomalies_SD>0:
            precision_SD=anomal_attacks_SD/anomalies_SD
            if ((precision_SD>0) and (recall_SD>0)): 
                F1_SD=2*precision_SD*recall_SD/(precision_SD+recall_SD)
            else:
                F1_SD=0
        else:
            precision_SD=0
            F1_SD=0
        
        if anomalies_OD>0:
            precision_OD=anomal_attacks_OD/anomalies_OD
            if ((precision_OD>0) and (recall_OD>0)): 
                F1_OD=2*precision_OD*recall_OD/(precision_OD+recall_OD)
            else:
                F1_OD=0
        else:
            precision_OD=0
            F1_OD=0
        
        df1=pd.Series(['null',0,0,0,0,0,0,0,0,0,0,0,F1_SD,F1_OD])
        df11=pd.DataFrame(df1).T
        df11.columns=df_eda_cols
        df_eda=df_eda.append(df11)
        
    
df_eda.to_csv("df_eda.csv")