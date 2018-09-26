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
import getopt
import logging
import time
import matplotlib.pyplot as plt
#import seaborn as sns; sns.set(style="ticks", color_codes=True)

home_dir='D:\\personal\\msc\\maccdc_2012\\'

#pr=np.arange(1,0,-0.1)
#rec=np.arange(0,1,0.1)
#rec2=np.arange(1,0.5,-0.05)
#f1=2*pr*rec/(pr+rec)
#fig, axes = plt.subplots(1, 1, sharex=True, sharey=True,figsize=(14,10))
#axes.plot(pr,f1)
#plt.xlabel("pr")
#plt.ylabel("rec")
#plt.legend(loc=2)
#plt.show()

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
#conn_fields= [  'duration',    'orig_bytes', 'orig_pkts', 'resp_bytes', 
#       'resp_pkts' ]


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


pcap_dir= 'maccdc2012_00002'

client = pymongo.MongoClient('localhost')
db = client['local']
collection_pcap = get_db()['inside_train_bro']
collection_bins= get_db()['bins']
finish=collection_pcap.count()
time_interval=180
#intervals=round(finish/interval_size)
df_collection = {}
df_feature_cols=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_pkts_intr','cumultv_pkt_count']

#doc_t=collection_pcap.find(sort=[('_Id',1)],limit=interval_size,skip=index*interval_size)
# # find first timestamp
first_doc= collection_pcap.find(sort=[('ts',1)],limit=1)
# # we received a collection of ONE,but we only care about the first timestamp
for dd in first_doc: first_ts=dd['ts']
# # find last timestamp
last_doc= collection_pcap.find(sort=[('ts',-1)],limit=1)
# # we received a collection of ONE,but we only care about the first timestamp
for dd in last_doc: last_ts=dd['ts']

intervals=1#math.ceil((last_ts-first_ts)/time_interval)

for index in range(intervals):
    if index==intervals-1:
        doc_tt=collection_pcap.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lte':last_ts}},{'$or':[{'orig_bytes':{'$gt':0}},{'service':{'$exists':'true'}}]}]})
    else:
        # # find from the timestamp, up to the pre-set time interval size
        # #  find only the flows whose 'orig_bytes'>0 => meaning they have some TCP-level activity
        doc_tt=collection_pcap.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':first_ts+time_interval}},{'$or':[{'orig_bytes':{'$gt':0}},{'service':{'$exists':'true'}}]}]})

    
    # # find from the timestamp, up to the pre-set time interval size
    #doc_tt=collection_pcap.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lte':last_ts}},{'$or':[{'orig_bytes':{'$gt':0}},{'service':{'$exists':'true'}}]}]})
    df =  pd.DataFrame(list(doc_tt)) 
    df_cnt=df.shape[0]
#    df['orig_pkts_intr']=df.orig_pkts/df.duration
#    df2=df.copy()
#    df2.ts=df2.ts.round()
#    df2['cumultv_pkt_count']=0
#    gb=df2.groupby(['id_orig_h','id_resp_h'])
#    ggtsdf=list()
#    gdict=gb.groups
#    for ss in gb.groups:
#        gtemp=gb.get_group(ss)
#        df3=gtemp.groupby(['ts']).sum()
#        gtsdf=df3.orig_pkts.median()
#        ggtsdf.append(gtsdf)
#        df2.iloc[gdict[ss].values,df2.columns.get_loc('cumultv_pkt_count')]=gtsdf
#
#    op_ser=pd.Series(ggtsdf,index=gdict.keys()) 
#    iqr=sci.stats.iqr(op_ser)
#    q3=op_ser.quantile(0.75)
#    cum_pkt_sec_th=q3+1.5*iqr
#    op_df=pd.DataFrame(op_ser)
#    
#    armean=op_ser.loc[op_ser>(cum_pkt_sec_th)].index
#    for sd in armean:
#        gtemp2=gb.get_group(sd)
#        op_df.loc[sd,'num']=gtemp2.shape[0]
#    
#    op_df=op_df.sort_values(by='num', ascending = False)
#    num_sum=op_df.num.sum()
#    outly_flws=0
#    outly_pairs=list()
#    for nn in op_df.num:
#        outly_flws+=nn
#        outly_pairs.append(op_df.loc[op_df.num==nn].index[0])
#        outly_th=0.25*(df_cnt-outly_flws)
#        if num_sum-outly_flws<outly_th:
#            break
#    rpy2.robjects.numpy2ri.activate()
#    rospca=importr("rospca")
#    robust_base=importr("robustbase")
#    for ppn in outly_pairs:
#        df_clean=df2[~df2.index.isin(gdict[ppn].values)]
#        df_clean=df_clean[df_feature_cols]
#        df_clean=df_clean.fillna(0)
#    ## hard to believe but pandas does NOT have a normalizing function
#    #df_norm=(df_clean-df_clean.mean())/df_clean.std()
#    df_mat=df_clean.as_matrix()
#    rpca=rospca.robpca(x=df_mat,mcd=True)
#    mcd=robust_base.covMcd(df_mat,cor = True, alpha=0.75)
#    loadings=np.array(rpca[0])
#    mcd_cov=np.array(mcd[3])
#    mcd_cor=np.array(mcd[6])
#    H0=np.array(rpca[5])
#    H1=np.array(rpca[6])
#    dfh_h0=df.iloc[H0-1]
#    df_clean["mcd"]=False
#    #df_clean[df_clean["mcd"]]
#    for hh in H0:
#        df_clean.iloc[hh-1,df_clean.columns.get_loc('mcd')]=True
#    
#    bin_lst=list(df._id)
#    mcd_lst=list(df2.loc[df_clean.loc[df_clean.mcd==True].index.values,'_id'])

    plt.ion()  
    fig, (ax11) = plt.subplots(1,1, figsize=(22,13))#sharex=True, sharey=True,
            
    conn_groups = df.groupby('attack')
    #srv_groups = sdf.groupby('srv_attack')
    ttl=list()
    
    for name, group in conn_groups:
        if name==0:
            ax11.scatter(x=group["SD"],y=group['OD'],label='no attack')
            #ttl.append(group['outlier_score'])
        else:
            ax11.scatter(x=group["SD"],y=group['OD'],label='attack')
           # ttl.append(group['outlier_score'])
            ax11.axhline(y=df.loc[df.OD_anomaly=='true','OD'].min() )
            ax11.axvline(x=df.loc[df.SD_anomaly=='true','SD'].min() )                       
            ax11.set_xlabel("Mahalanobis DIstance (SD)  F1=")#+str(round(conn_SD_F1,2)))
            ax11.set_ylabel("PCA residuals (OD) F1=")#+str(round(conn_OD_F1,2)))
            ax11.set_title('TCP Connection Analysis')
            ax11.legend(loc='upper left')
    plt.show()
            
    fig.savefig(str('inside_train_biplot.png'),bbox_inches='tight')  

 
    from sklearn.metrics import roc_curve, roc_auc_score,precision_recall_curve,f1_score
    lambda_c=[0.12]#list(np.arange(0.13,0.15,0.03))
    fig_plot, (ax_roc,ax_pr) = plt.subplots(1,2, sharex=True, sharey=True,figsize=(20,18))
    ax_roc.set_xlim([-0.05,1.05])
    ax_roc.set_ylim([-0.05,1.05])
    ax_roc.set_xlabel('False Positive Rate')
    ax_roc.set_ylabel('True Positive Rate')
    ax_roc.set_title('ROC Curve')
    
    ax_pr.set_xlim([-0.05,1.05])
    ax_pr.set_ylim([-0.05,1.05])
    ax_pr.set_xlabel('Recall')
    ax_pr.set_ylabel('Precision')
    ax_pr.set_title('PR Curve')
    auc_list=list()
    f1_list=list()
    #alpha=list(np.arange(0.95,0.55,-0.05))
    alpha=0.95
    for ll,k in zip(lambda_c,'b'):#grc'):#mykw'):
    
        
        df_target=pd.DataFrame(index=df.index)
        df_target['attack']=df.attack#df.attack_bool.apply(lambda x: 1 if x==True else 0).astype(int)
        df_target['SD_anomaly']=df.SD_anomaly.apply(lambda x: 1 if x=='true' else 0)
        df_target['OD_anomaly']=df.OD_anomaly.apply(lambda x: 1 if x=='true' else 0)
        df_target['attack_pred']=0
        df_target.loc[(df_target.SD_anomaly>0)|((df_target.OD_anomaly>0) & (df_target.SD_anomaly<1)),'attack_pred']=1
        tpr,fpr,_ = roc_curve(df_target.attack,df_target.attack_pred)
        roc_auc = roc_auc_score(df_target.attack,df_target.attack_pred)
        auc_list.append(roc_auc)
        per,rec,_pr= precision_recall_curve(df_target.attack,df_target.attack_pred)
        f1_scr= f1_score(df_target.attack,df_target.attack_pred)
        f1_list.append(f1_scr)
        ax_roc.plot(tpr,fpr,c=k,label=(ll,round(roc_auc,2)))
        ax_pr.plot(rec,per,c=k,label=(ll,round(f1_scr,2)))
        
    ax_roc.legend(loc='lower left')
    ax_pr.legend(loc='lower left')
    plt.show()
    fig_plot.savefig('inside_train_roc.png')
    
    crit_lambda=lambda_c[f1_list.index(np.max(f1_list))]
    
    print('motek')    
    first_ts+=time_interval  
    
    
    
   
    #'method_pair_freq',
#       'status_code_pair_freq', 'user_agent_pair_freq', 'orig_mime_types_pair_freq',
#       'resp_mime_types_pair_freq',


#    df19=pd.DataFrame()
#    dff19=pd.DataFrame()
#    dff19=dff19.from_csv('dff_maccdc2012_00001_bin_9.csv')
#    df19=df19.from_csv('df_maccdc2012_00001_http_bin_9.csv')
#    
#    df_clean["attack_bool"]=True
#    df_clean["attack_bool"][df["attack_bool"]==False]=False
#    fig=plt.figure(figsize=(24,16))
#    #fig, axes = plt.subplots(1, 1, sharex=True, sharey=True)
#    colors = {0: 'red', 1: 'aqua'}
#    markers={1:"o",0:"p"}
#   
#    
#    df=df19
#    groups = df.groupby('attack_bool')
#
#    fig, axes = plt.subplots(1, 1, sharex=True, sharey=True,figsize=(14,10))
#
#    for name, group in groups:   
#            if name==False:
#                axes.scatter(x=group["SD"],y=group['OD'],label='no attack')
#            else:
#                axes.scatter(x=group["SD"],y=group['OD'],label='attack')
#                plt.axhline(y=df.loc[df.OD_anomaly==True,'OD'].min() )
#                plt.axvline(x=df.loc[df.SD_anomaly==True,'SD'].min() )                       
#                plt.xlabel("Mahalanobis DIstance (SD)")
#                plt.ylabel("PCA residuals (OD)")
#                plt.legend(loc=2)
#                plt.show()
#    
#    
#    
#    
#    
#    
#    
#    
#    
#    
#    
#    for name, group in groups:   
#            if name==False:
#                axes.scatter(x=group["orig_bytes"],y=group["resp_bytes"],c=group.mcd.map(colors),marker='o',label='no attack',vmin=0, vmax=4)
#                #plt.show()
#            else:
#                axes.scatter(x=group["orig_bytes"],y=group["resp_bytes"],c=group.mcd.map(colors),marker='p',label='attack',vmin=0, vmax=4)                       
#                plt.show()
#    #axes.scatter(x=df_clean["orig_bytes"],y=df_clean["resp_bytes"],c=df_clean.mcd.map(colors))
#    #ax.legend()
#    plt.show()
#    fig.savefig('biplot.png',bbox_inches='tight')  
#    print("finished pca")
#    
#    
    
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