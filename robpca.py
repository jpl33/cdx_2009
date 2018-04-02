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
from statsmodels.multivariate.pca import PCA
from sklearn import decomposition
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


#c*(m − p + 1)/(p*m)*d2 S∗(Xi, X¯ ∗) ∼· F(p,m−p+1)



def unset_vars():
    collection_pcap.update_many({'bin':{'$exists':True}},{'$unset':{'orig_pkts_intr':'','mcd':'','bin':''}},upsert=False)

def robust_f_m_param(n,p,h):
    #h=(n+p+1)/2
    a=1-h
    qa=sci.stats.chi2.isf(a,df=p)
    d=sci.stats.chi2.cdf(qa,p+2)
    ca=h/(d)
    c2=-d/2
    c3=-(sci.stats.chi2.cdf(qa,p+4))/2
    c4=3*c3
    b1=ca*(c3-c4)/h
    b2=.5+(ca/h)*(c3-(qa/p)*(c2+h/2))
    v1=h*(b1**2)*(a*((ca*qa/p-1)**2)-1)-2*c3*(ca**2)*3*((b1-p*b2)**2)+(p+2)*b2*(2*b1-p*b2)
    v2=n*((b1*(b1-p*b2)*h)**2)*(ca**2)
    v=v1/v2
    M_asy=2/((ca**2)*v)
    M_pred=M_asy*math.exp(0.725-.00663*p-0.0780*math.log(n))
    if n<1000:
        return  M_pred
    else:
        return M_asy
    

def robust_f_c_param(n,p,h):
    c1=sci.stats.chi2.ppf(h,df=p)
    c2=sci.stats.chi2.cdf(c1,df=p+2)
    return c2/h

def which_feature_SD(df_row,pca_cov):
    numer2=pca_cov.dot(df_row.T)
    feat_list_x=list()
    for n in range(0,numer2.shape[1]):
        feat_list_i=list()
        for ni in range(0,numer2.shape[0]):
            feat_list_i.append(numer2[ni][n]**2/pca_cov[ni][ni] )
        feat_list_x.append(df_row.columns[feat_list_i.index(max(feat_list_i))])
    return feat_list_x


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
    df['cumultv_pkt_count']=0
    
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
        # # set 'cumultv_pkt_count' for all indexes that belong to orig-resp pair
        df.iloc[gdict[ss].values,df.columns.get_loc('cumultv_pkt_count')]=gtsdf
    
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
    
    for ppn in outly_pairs:
        # # dump all flows belonging to orig-resp pairs in outly_pairs from the overall bin flows
        df_clean=df2[~df2.index.isin(gdict[ppn].values)]
        df_clean=df_clean[df_feature_cols]
        df_clean=df_clean.fillna(0)
    
    df_c_n=(df_clean-df_clean.mean())/df_clean.std(ddof=0)
    df3=df[df_feature_cols]
    df3_norm=(df3-df_clean.mean() )/df_clean.std(ddof=0)
    dirty_flws=list(set(df3.index.values)-set(df_clean.index.values))
    
    df_mat=df_c_n.as_matrix()
    
    rpy2.robjects.numpy2ri.activate()
    rospca=importr("rospca")
    rpca=rospca.robpca(x=df_mat,mcd=True,ndir=5000)
    loadings=np.array(rpca[0])
    e_vals=np.array(rpca[1])
    scores=np.array(rpca[2])
    center=np.array(rpca[3])
    H0=np.array(rpca[5])
    H1=np.array(rpca[6])
    SD=np.array(rpca[9])
    OD=np.array(rpca[10])
    SD_th=np.array(rpca[11])
    OD_th=np.array(rpca[12])
    SD_flag=np.array(rpca[13])
    OD_flag=np.array(rpca[14])
   
    
    sc_3=(df3_norm.as_matrix()-center).dot(loadings)
    sd_3=pd.DataFrame()
    
    for cc in range(0,sc_3.shape[1]):
        sd_3[cc]=sc_3[:,cc]**2/e_vals[cc]
        
    
    sd_3['sd_mine']=sd_3.iloc[:,0:sc_3.shape[1]].sum(axis=1)
    sd_3['sd_mine']=np.sqrt(sd_3['sd_mine'].values)
    sd_3['sd_flag']=1
    sd_3.loc[sd_3.sd_mine>SD_th[0],'sd_flag']=0
    
    num_e_vals=e_vals.shape[0]
    lambda_mat=e_vals*np.identity(num_e_vals)    
    pca_cov=(loadings.dot(lambda_mat)).dot(loadings.T)
    
    feat_vec=which_feature_SD(df3_norm.loc[sd_3.sd_mine>SD_th[0],:],pca_cov)
    
    
    df3_od=(df3_norm-center)-(loadings.dot(sc_3.T)).T
    sd_3['od_mine']=0
    sd_3['od_mine']=np.sqrt((df3_od**2).sum(axis=1))
    sd_3['od_flag']=1
    sd_3.loc[sd_3.od_mine>OD_th[0],'od_flag']=0
#    feat_vec0=np.repeat(0,df_clean.shape[1])
#    feat_list=list()
#    i=0
#    feat_vec1=feat_vec0
#    for n in range(0,df_c_n.shape[1]):
#        feat_vec1[i]=1
#        print(feat_vec1)
#        denom=feat_vec1.dot(pca_cov).dot(feat_vec1.T)
#        numer=feat_vec1.dot(pca_cov).dot(df_c_n.iloc[0].values)
#        feat_list.append(numer**2/denom  )
#        feat_vec1[i]=0
#        i+=1
#    
    
   

#    time_df_c_n=timeit.default_timer()
#    rpca=rospca.robpca(x=df_c_n.as_matrix(),mcd=True)
#    elapsed_df_c_n=timeit.default_timer()-time_df_c_n
#    
#    time_df_clean=timeit.default_timer()
#    rpca=rospca.robpca(x=df_clean.as_matrix(),mcd=True)
#    elapsed_df_clean=timeit.default_timer()-time_df_clean
#    
    
#    time_df3=timeit.default_timer()
#    rpca=rospca.robpca(x=df3.as_matrix(),mcd=True)
#    elapsed_df3=timeit.default_timer()-time_df3
#    
#    time_df3_norm=timeit.default_timer()
#    rpca=rospca.robpca(x=df3_norm.as_matrix(),mcd=True)
#    elapsed_df3_norm=timeit.default_timer()-time_df3_norm
#    
    
    
    
    dfh_h0=df.iloc[H0-1]
    df_clean["mcd"]=False
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
    
    
    llp=json.dumps(outly_pairs)
    
    collection_bins.update_one({'pcap_dir':pcap_dir,'index':index},{'$set':{'mcd_cor':mcd_dict,'outlying_pairs':llp}},upsert=False)
    
    
#    mcd_df2=pd.read_json(json.dumps(mcd_dict))
#    llp=json.loads(llp)







#    projected_df_c=pca_df_c.factors
#    e_vals_sum=e_vals.sum()
#    k_v=0
#    sum_e_vals=0
#    for vv in e_vals:
#        if sum_e_vals<0.8*e_vals_sum:
#            k_v+=1
#            sum_e_vals+=vv
#     
#    proj_df_c=projected_df_c.iloc[:,:k_v]
#    
#    df_c_corr=df_norm.cov()
#    df_c_corr2=np.corrcoef(df_clean,rowvar=False)
#    dfc_vals,dfc_vecs=np.linalg.eig(df_c_corr2)
#    sum_dfc_vals=dfc_vals.sum()
#    k_v=0
#    sum_e_vals=0
#    for vv in dfc_vals:
#        if sum_e_vals<0.8*sum_dfc_vals:
#            k_v+=1
#            sum_e_vals+=vv
#    

#    
#    skpca=decomposition.PCA(df_norm)

  
