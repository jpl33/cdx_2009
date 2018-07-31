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
        norm_gauss=norm_gauss.abs()
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

services=['http']#,'ftp','dns']#,'ssl',
pcap_dirs= ['maccdc2012_00004']#,'maccdc2012_00005','maccdc2012_00006']#'maccdc2012_00001','maccdc2012_00002','maccdc2012_00003']

ensemble_df=pd.DataFrame()

for pp in pcap_dirs:
    for srv in services:
    
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
                conn_doc_tt=conn_collection.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lte':last_ts}},{'$or':[{'orig_bytes':{'$gt':0}},{'service':{'$exists':'true'}}]}]})
            else:
                # # find from the timestamp, up to the pre-set time interval size
                # #  find only the flows whose 'orig_bytes'>0 => meaning they have some TCP-level activity
                srv_doc_tt=service_collection.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':first_ts+time_interval}}]})#,{'orig_bytes':{'$gt':0}}
                conn_doc_tt=conn_collection.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':first_ts+time_interval}},{'$or':[{'orig_bytes':{'$gt':0}},{'service':{'service':'true'}}]}]})
          
            srv_df =  pd.DataFrame(list(srv_doc_tt)) 
            conn_df =  pd.DataFrame(list(conn_doc_tt)) 
            # # number of flows in bin
            srv_df_cnt=srv_df.shape[0]
            conn_df_cnt=conn_df.shape[0]
            if (conn_df_cnt<20)| (srv_df_cnt<20):
                first_ts+=time_interval
                continue
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
            # # select all uid in srv_df AND conn_df from the srv_df uid
            lsr=[x if x in set(conn_df.uid) else 0 for x in srv_df.uid]
            lsr=[l for l in lsr if l!=0]
            lsr=list(set(lsr))
            sdf=pd.DataFrame()
            sdf_columns=['pcap_dir','index','uid','conn_attack','conn_SD','conn_SD_norm','conn_OD','conn_OD_norm','service','srv_attack','srv_ts','srv_SD','srv_SD_norm','srv_OD','srv_OD_norm','total_outlier_score']
            # # for all the uid in both DataFrames set the service SD,OD,norm_SD,norm_OD, service attacks
            for uu in lsr:
                rr=srv_df.loc[srv_df.uid==uu]
                msg=str( 'pcap_dir:'+pp+':service:'+srv+': index:'+str(index)+': processing '+str(rr.shape[0])+' application requests, out of '+str(srv_df.shape[0])+'. '+str(lsr.index(uu))+' out of '+str(len(lsr))+' uids' )
                myLogger.error(msg)
                for i in rr.index.values:
                    srf=pd.Series([pp,
                                   index,
                                   uu,
                                   sdd.loc[sdd.uid==uu,'conn_attack'].values[0],
                                   sdd.loc[sdd.uid==uu,'conn_SD'].values[0],
                                   sdd.loc[sdd.uid==uu,'conn_SD_norm'].values[0],
                                   sdd.loc[sdd.uid==uu,'conn_OD'].values[0],
                                   sdd.loc[sdd.uid==uu,'conn_OD_norm'].values[0],
                                   srv,
                                   json_bool(rr.loc[i,'attack_bool']),
                                   rr.loc[i,'ts'],
                                   rr.loc[i,'SD'],
                                   rr.loc[i,'SD_norm'],
                                   rr.loc[i,'OD'],
                                   rr.loc[i,'OD_norm'],
                                   0 ])
                    df_r1=pd.DataFrame(srf).T
                    df_r1.columns=sdf_columns
                    
                    conn_sd=df_r1.conn_SD
                    conn_sd_norm=df_r1.conn_SD_norm
                    conn_od=df_r1.conn_OD
                    conn_od_norm=df_r1.conn_OD_norm
                    srv_sd=df_r1.srv_SD
                    srv_sd_norm=df_r1.srv_SD_norm
                    srv_od=df_r1.srv_OD
                    srv_od_norm=df_r1.srv_OD_norm
                    df_r1['total_outlier_score']=( (srv_sd_norm)+(srv_od_norm)+(conn_sd_norm)+(conn_od_norm))/4
                    sdf=sdf.append(df_r1)
                
            ensemble_df=ensemble_df.append(sdf)
           
            plt.ion()  
            fig, ((ax11,ax12,ax13,ax14)) = plt.subplots(1,4, figsize=(22,10))#sharex=True, sharey=True,
            
            conn_groups = sdf.groupby('conn_attack')
            srv_groups = sdf.groupby('srv_attack')
            ttl=list()
            for name, group in conn_groups:
                if name==False:
                    ax11.scatter(x=group["conn_SD"],y=group['conn_OD'],label='no attack')
                    ttl.append(group['total_outlier_score'])
                else:
                    ax11.scatter(x=group["conn_SD"],y=group['conn_OD'],label='attack')
                    ttl.append(group['total_outlier_score'])
                    ax11.axhline(y=conn_df.loc[conn_df.OD_anomaly==True,'OD'].min() )
                    ax11.axvline(x=conn_df.loc[conn_df.SD_anomaly==True,'SD'].min() )                       
                    ax11.set_xlabel("Mahalanobis DIstance (SD)")
                    ax11.set_ylabel("PCA residuals (OD)")
                    ax11.set_title('TCP Connection Analysis')
                    ax11.legend(loc=2)
                    
            for name, group in srv_groups:
                if name==False:
                    ax12.scatter(x=group["srv_SD"],y=group['srv_OD'],label='no attack')
                    ttl.append(group['total_outlier_score'])
                else:
                    ax12.scatter(x=group["srv_SD"],y=group['srv_OD'],label='attack')
                    ttl.append(group['total_outlier_score'])
                    ax12.axhline(y=srv_df.loc[srv_df.OD_anomaly==True,'OD'].min() )
                    ax12.axvline(x=srv_df.loc[srv_df.SD_anomaly==True,'SD'].min() )                       
                    ax12.set_xlabel("Mahalanobis DIstance (SD)")
                    ax12.set_ylabel("PCA residuals (OD)")
                    ax12.set_title('HTTP application analysis')
                    ax12.legend(loc=2)

            #colors=['red','green','blue','yellow']
            #fig, ax13 = plt.subplots(1, 1, figsize=(14,10))#sharex=True, sharey=True,
            
            ax13.hist(ttl,label=['conn_attack_false','conn_attack_true','srv_attack_false','srv_attack_true'])
            ax13.set_xlabel('total_outlier_score')
            ax13.set_ylabel('count')
            ax13.set_title('attack/non-attack histograms')
            ax13.legend(loc=2)
            gg=sdf.total_outlier_score.value_counts()
            ggl1=gg.index.values
            ggl2=gg.values
            poly1=np.polyfit(ggl1,ggl2,10)
            poly2=np.poly1d(poly1)
            ax14.plot(sdf.total_outlier_score,poly2(sdf.total_outlier_score),'g^')
            #ax14.hist(sdf.total_outlier_score,histtype='step')
            ax14.set_xlabel('total_outlier_score')
            ax14.set_ylabel('count')
            ax14.set_title('fitted curve')
            ax14.legend(loc=2)
            plt.show()
            
            fig.savefig(str('conn_'+srv+'_'+pp+'_bin'+str(index)+'.png'),bbox_inches='tight')  
            first_ts+=time_interval

#                    
#            df_s1=pd.Series([service_collection_name,
#                                index,
#                                df_cnt,
#                                df.loc[df.attack_bool==True].shape[0],
#                                df.loc[df.mcd=='true'].shape[0],
#                                mcd_attacks,
#                                df.loc[df.SD_anomaly=='true'].shape[0],
#                                SD_recall,
#                                SD_precision,
#                                df.loc[df.OD_anomaly=='true'].shape[0],
#                                OD_recall,
#                                OD_precision,
#                                0,
#                                0
#                               ])
#            df_r1=pd.DataFrame(df_s1).T
#            df_r1.columns=df_eda_cols
#            if SD_precision>0:
#                SD_F1=2*df_r1.SD_anomaly_percision*df_r1.SD_anomaly_recall/(df_r1.SD_anomaly_percision+df_r1.SD_anomaly_recall)
#            else:
#                SD_F1=0
#            if OD_recall>0:
#                if OD_precision>0:
#                    OD_F1=2*df_r1.OD_anomaly_percision*df_r1.OD_anomaly_recall/(df_r1.OD_anomaly_percision+df_r1.OD_anomaly_recall)
#                else:
#                    OD_F1=0
#            else:
#                OD_F1=0
#            
#            df_r1['SD_F1']=SD_F1
#            df_r1['OD_F1']=OD_F1
#            df_eda=df_eda.append(df_r1)
#            first_ts+=time_interval
#        df_eda_pp=df_eda.loc[df_eda.collection==pp]
#        srv_lst=[x if x==service_collection_name else 0 for x in df_eda.collection ]
#        df_eda_pp=df_eda.loc[df_eda.collection.isin(srv_lst)]
#        anomal_attacks_SD=(df_eda_pp.SD_anomaly_recall*df_eda_pp.attack_bool_count).sum()
#        attacks=df_eda_pp.attack_bool_count.sum()
#        anomalies_SD=df_eda_pp.SD_anomaly.sum()
#        anomal_attacks_OD=(df_eda_pp.OD_anomaly_recall*df_eda_pp.attack_bool_count).sum()
#        anomalies_OD=df_eda_pp.OD_anomaly.sum()
#        if attacks==0:
#            recall_SD=0
#            recall_OD=0
#        else:
#            recall_SD=anomal_attacks_SD/attacks
#            recall_OD=anomal_attacks_OD/attacks
#        if anomalies_SD>0:
#            precision_SD=anomal_attacks_SD/anomalies_SD
#            if ((precision_SD>0) and (recall_SD>0)): 
#                F1_SD=2*precision_SD*recall_SD/(precision_SD+recall_SD)
#            else:
#                F1_SD=0
#        else:
#            precision_SD=0
#            F1_SD=0
#        
#        if anomalies_OD>0:
#            precision_OD=anomal_attacks_OD/anomalies_OD
#            if ((precision_OD>0) and (recall_OD>0)): 
#                F1_OD=2*precision_OD*recall_OD/(precision_OD+recall_OD)
#            else:
#                F1_OD=0
#        else:
#            precision_OD=0
#            F1_OD=0
#        
#        df1=pd.Series(['null',0,0,0,0,0,0,0,0,0,0,0,F1_SD,F1_OD])
#        df11=pd.DataFrame(df1).T
#        df11.columns=df_eda_cols
#        df_eda=df_eda.append(df11)
        
    
ensemble_df.to_csv("ensemble_df.csv")