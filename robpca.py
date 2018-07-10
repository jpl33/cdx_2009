
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
        if isinstance(obj, np.bool_):
            return str(obj).lower()
        return json.JSONEncoder.default(self, obj)

def json_bool(obj):
    if isinstance(obj, bool):
            return str(obj).lower()
    if isinstance(obj, np.bool_):
            return str(obj).lower()
    return obj



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

def orig_category_frequency_vectors(df2,feature_list):
    for ft in df2[feature_list]:
        column_name=ft+'_orig_freq'
        ft_freq=df2[ft].value_counts()/df2.shape[0]
        for category in ft_freq.index.values:
            df2.loc[df2[ft]==category,column_name]= ft_freq.loc[category] 
    return df2


df_feature_cols1=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_pkts_size','orig_pkts_intr','orig_pkts_diff','resp_pkts_diff','ts_diff','service_orig_freq','history_orig_freq','conn_state_orig_freq','orig_to_resp_freq']# 'service_freq','history_freq','conn_state_freq',



category_features=['service','history','conn_state','resp_to_orig','orig_to_resp']
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
        doc_tt=collection_pcap.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lte':last_ts}},{'$or':[{'orig_bytes':{'$gt':0}},{'service':{'$exists':'true'}}]}]})
    else:
        # # find from the timestamp, up to the pre-set time interval size
        # #  find only the flows whose 'orig_bytes'>0 => meaning they have some TCP-level activity
        doc_tt=collection_pcap.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':first_ts+time_interval}},{'$or':[{'orig_bytes':{'$gt':0}},{'service':{'$exists':'true'}}]}]})

    df =  pd.DataFrame(list(doc_tt)) 
    # # number of flows in bin
    df_cnt=df.shape[0]
    # # origin_pkts interval per flow
    df['orig_pkts_intr']=df.orig_pkts/df.duration
    
    df['orig_pkts_size']=df.orig_bytes/df.orig_pkts
     
    df['orig_to_resp']=float(0)
    df['resp_to_orig']=float(0)

    for feature in category_features:
            df[feature+'_freq']=0.0
            ft_freq=df[feature].value_counts()/df_cnt
            for idd in ft_freq.index.values:
                df.loc[df[feature]==idd,feature+'_freq']= ft_freq.loc[idd]
                
    # # prepping df pairwise feature columns
    orig_category_features=[x+'_orig_freq'  for x in category_features]
    for feature in orig_category_features:
            df[feature]=0.0 
    # # prepping df pairwise jsd feature columns
    jsd_category_features=[x+'_jsd'  for x in category_features]
    for feature in jsd_category_features:
            df[feature]=0.0 
    
    
    df2=df.copy()
    #df2.ts=df2.ts.round()
    # # cumulative origin pkts per second for  orig-resp pairs
    df2['cumultv_pkt_count']=float(0)
    df['cumultv_pkt_count']=float(0)
    df['orig_pkts_diff']=float(0)
    df['resp_pkts_diff']=float(0)
    df['ts_diff']=float(0)
    
    msg='start looking for bad flows. Line205'
    myLogger.error(msg)
    
    
    gb=df2.groupby(['id_orig_h','id_resp_h'])
    ggtsdf=list()
    gdict=gb.groups
    df4=pd.DataFrame(list(zip(*gb.groups.keys())))
    df4=df4.T
    df4.columns=['id_orig_h','id_resp_h']
    df4['flows']=float(0)
    df4['resp_to_orig']=float(0)
    df4['orig_to_resp']=float(0)
    anomal_lst=[x if x in df4.id_resp_h.values else 0 for x in df4.id_orig_h]
    anomal_lst=list(set(anomal_lst))
    anomal_lst.remove(0)
    

    
    # # iterate over orig-resp pairs, aggregate flows per second, and get the median of the origin pkts sent
    for ss in gb.groups:
        gtemp=gb.get_group(ss)
        gtemp2=gtemp.copy()
        gtemp.loc[:,'orig_pkts_diff']=gtemp['orig_pkts'].diff()
        df.loc[gtemp.index.values,'orig_pkts_diff']=gtemp['orig_pkts'].diff()
        gtemp.loc[:,'resp_pkts_diff']=gtemp['resp_pkts'].diff()
        df.loc[gtemp.index.values,'resp_pkts_diff']=gtemp['resp_pkts'].diff()
        gtemp.loc[:,'ts_diff']=gtemp['ts'].diff()
        df.loc[gtemp.index.values,'ts_diff']=gtemp['ts'].diff()
        
        gtemp2.ts=gtemp.ts.round()
        df4.loc[(df4.id_orig_h==ss[0])&(df4.id_resp_h==ss[1]),'flows']=gtemp.shape[0]        
        df3=gtemp2.groupby(['ts']).sum()
        gtsdf=df3.orig_pkts.median()
        # # ggtsdf is list of all pairs origin_pkts/second medians
        ggtsdf.append(gtsdf)
        # # set 'cumultv_pkt_count' for all indexes that belong to orig-resp pair
        df2.iloc[gdict[ss].values,df2.columns.get_loc('cumultv_pkt_count')]=gtsdf
        # # set 'cumultv_pkt_count' for all indexes that belong to orig-resp pair
        df.iloc[gdict[ss].values,df.columns.get_loc('cumultv_pkt_count')]=gtsdf
    
    for src in anomal_lst:
        if df4.loc[df4.id_orig_h==src,'flows'].sum()>df4.loc[df4.id_resp_h==src,'flows'].sum():
            df4.loc[df4.id_resp_h==src,'orig_to_resp']=1
            df.loc[df.id_resp_h==src,'orig_to_resp']=1
        else:   
            df4.loc[df4.id_orig_h==src,'resp_to_orig']=1
            df.loc[df.id_orig_h==src,'resp_to_orig']=1
    df=df.fillna(0)
    for ft in ['orig_to_resp','resp_to_orig']:
        ft_freq=df[ft].value_counts()/df_cnt
        for idd in ft_freq.index.values:
            df.loc[df[ft]==idd,ft+'_freq']= ft_freq.loc[idd]
    
    gb1=df.groupby('id_orig_h')
    for orig in gb1.groups:
        gtemp1=gb1.get_group(orig)
        cc=category_features[0:4]
        gtemp1=orig_category_frequency_vectors(gtemp1,cc)
        for feature in category_features:
#            gtemp[feature+'_pair_freq']=gtemp[feature+'_pair_freq']
            gtemp1[feature+'_jsd']=jsd(gtemp1[feature+'_freq'],gtemp1[feature+'_orig_freq'])
        
        for ind in gtemp1.index.values:
            for feature in category_features:
                fi=category_features.index(feature)
                df.loc[ind,orig_category_features[fi]]=gtemp1.loc[ind,orig_category_features[fi]]
                df.loc[ind,jsd_category_features[fi]]=gtemp1.loc[ind,jsd_category_features[fi]]

    
            
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
    for nn in op_df.index:
        outly_flws+=float(op_df.loc[op_df.index==nn].num)
        outly_pairs.append(nn)
        # # are the flows of the rest of the pairs less than 25% of available flows? if so, they won't affect the MCD.
        outly_th=0.25*(df_cnt-outly_flws)
        if num_sum-outly_flws<outly_th:
            break
    msg='finish looking for bad flows. Line252: directory= '+pcap_dir+':index='+str(index)
    myLogger.error(msg)
    
    df_clean=df.copy()
    for ppn in outly_pairs:
        # # dump all flows belonging to orig-resp pairs in outly_pairs from the overall bin flows
        df_clean=df_clean[~df_clean.index.isin(gdict[ppn].values)]
        df_clean=df_clean[df_feature_cols1]
        df_clean=df_clean.fillna(0)
    
    df_c_n=(df_clean-df_clean.mean())/df_clean.std(ddof=0)
    df_c_n=df_c_n.fillna(0)
    df3=df[df_feature_cols1]
    df3_norm=(df3-df_clean.mean() )/df_clean.std(ddof=0)
    #df3_norm=(df3-df3.mean() )/df3.std(ddof=0)
    dirty_flws=list(set(df3.index.values)-set(df_clean.index.values))
    
    #df_mat=df3_norm.as_matrix()
    df_mat=df_c_n.as_matrix()
    
    msg='start first robpca. Line269: directory= '+pcap_dir+':index='+str(index)
    myLogger.error(msg)
    
    rpy2.robjects.numpy2ri.activate()
    rospca=importr("rospca")
    rpca=rospca.robpca(x=df_mat,mcd=False,ndir=5000)
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
    
   

    

    # # standardized Data Frame- robust PCA center multiplied by the PCA loadings, will give us our PCA scores
    sc_3=(df3_norm.as_matrix()-center).dot(loadings)
    sd_3=pd.DataFrame()
    
    msg='start first OD, SD compute. Line310: directory= '+pcap_dir+':index='+str(index)
    myLogger.error(msg)
    
    # # compute SD - Square mahalanobis Distance, for each PCA loading
    for cc in range(0,sc_3.shape[1]):
        sd_3[cc]=sc_3[:,cc]**2/e_vals[cc]
        
    # # sum the SD's up and take their  sqrt() for the total SD
    sd_3['sd_mine']=sd_3.iloc[:,0:sc_3.shape[1]].sum(axis=1)
    sd_3['sd_mine']=np.sqrt(sd_3['sd_mine'].values)
    sd_3['sd_flag']=1
    sd_3.loc[sd_3.sd_mine>SD_th[0],'sd_flag']=0
    
    # #  compute the PCA sub-space covariance matrix
    num_e_vals=e_vals.shape[0]
    lambda_mat=e_vals*np.identity(num_e_vals)    
    pca_cov=(loadings.dot(lambda_mat)).dot(loadings.T)
    
    # # find the most influential feature for anomalous SD values
    feat_vec_sd=which_feature_SD(df3_norm.loc[sd_3.sd_mine>SD_th[0],:],pca_cov)
    sd_3['SD_feature']=0
    sd_3.loc[sd_3.sd_mine>SD_th[0],'SD_feature']=feat_vec_sd
    
    # # multiply PCA scores by the PCA loadings to get predicted X, "X-hat"
    # # then, sbtract that from the original data to gat the PCA residuals or Orthogonal Distance, Od
    df3_od=(df3_norm-center)-(loadings.dot(sc_3.T)).T
    sd_3['od_mine']=0
    sd_3['od_mine']=np.sqrt((df3_od**2).sum(axis=1))
    sd_3['od_flag']=1
    sd_3.loc[sd_3.od_mine>OD_th[0],'od_flag']=0
    # # find the most influential feature for anomalous OD values
    feat_vec_od=which_feature_OD(df3_od.loc[sd_3.od_mine>OD_th[0],:])
    sd_3['OD_feature']=0
    sd_3.loc[sd_3.od_mine>OD_th[0],'OD_feature']=feat_vec_od
   
    df['SD']=sd_3.sd_mine
    df['SD_anomaly']=False
    df.loc[sd_3.sd_flag==0,'SD_anomaly']=True
    df['SD_feature']=False
    df.loc[sd_3.SD_feature!=0,'SD_feature']=feat_vec_sd
    df['OD']=sd_3.od_mine
    df['OD_anomaly']=False
    df.loc[sd_3.od_flag==0,'OD_anomaly']=True
    df['OD_feature']=False
    df.loc[sd_3.OD_feature!=0,'OD_feature']=feat_vec_od
    
    # # find df_clean index that was used for mcd
    #mcd_index=df3_norm.iloc[H1==1].index.values
    mcd_index=df_c_n.iloc[H1==1].index.values
    
    df["mcd"]=False
    #df.loc[df3_norm.iloc[H1==1].index.values,'mcd']=True
    df.loc[df_c_n.iloc[H1==1].index.values,'mcd']=True
     
    msg='start single line write to mongo . Line470: directory= '+pcap_dir+':index='+str(index)
    myLogger.error(msg)
    
 
    bin_lst=list(df._id)
    
    df.to_csv(str('df_'+pcap_dir+'_'+'bin_'+str(index)+'.csv'))
    collection_pcap.update_many({'_id': {'$in': bin_lst}},{'$set':{'bin':index}})

    msg='start bulk write to mongo. Line565: directory= '+pcap_dir+':index='+str(index)
    myLogger.error(msg)
    
    
    from pymongo import UpdateOne
    time_bulk=timeit.default_timer()
    d=0
    bulk=collection_pcap.initialize_unordered_bulk_op()
    write_list=list()
    for idd in bin_lst:   
        write_list.append(UpdateOne({'_id':idd},{'$set':{'orig_to_resp_freq':df.loc[df._id==idd,'orig_to_resp_freq'].values[0]
                                                    ,'orig_pkts_diff':df.loc[df._id==idd,'orig_pkts_diff'].values[0]
                                                    ,'resp_pkts_diff':df.loc[df._id==idd,'resp_pkts_diff'].values[0]
                                                    ,'ts_diff':df.loc[df._id==idd,'ts_diff'].values[0]
                                                    ,'orig_pkts_intr':df.loc[df._id==idd,'orig_pkts_intr'].values[0]
                                                    ,'orig_pkts_size':df.loc[df._id==idd,'orig_pkts_size'].values[0]
                                                    ,'cumultv_pkt_count':df.loc[df._id==idd,'cumultv_pkt_count'].values[0]
                                                    ,'service_orig_freq':df.loc[df._id==idd,'service_orig_freq'].values[0]
                                                    ,'history_orig_freq':df.loc[df._id==idd,'history_orig_freq'].values[0]
                                                    ,'conn_state_orig_freq':df.loc[df._id==idd,'conn_state_orig_freq'].values[0]
                                                    ,'mcd':json_bool(df.loc[df._id==idd,'mcd'].values[0])
                                                    ,'SD':json_bool(df.loc[df._id==idd,'SD'].values[0])
                                                    ,'SD_anomaly':json_bool(df.loc[df._id==idd,'SD_anomaly'].values[0])
                                                    ,'SD_feature':json_bool(df.loc[df._id==idd,'SD_feature'].values[0])
                                                    ,'OD':json_bool(df.loc[df._id==idd,'OD'].values[0])
                                                    ,'OD_anomaly':json_bool(df.loc[df._id==idd,'OD_anomaly'].values[0])
                                                    ,'OD_feature':json_bool(df.loc[df._id==idd,'OD_feature'].values[0])
                                                    }}))
        if (len(write_list)%500==0):
            try:
                collection_pcap.bulk_write(write_list,ordered=False)
            except Exception as e: 
                error=str(e)+':pcap_dir='+pcap_dir+':bin='+str(bin)+':batch='+str(d)+':error on bulk write to mongo'
                myLogger.error(error)
            write_list=list() 
            msg='wrote bulk to mongo. Line520: directory= '+pcap_dir+':index='+str(index)+':batch='+str(d)+': write_list size:'+str(len(write_list))
            d+=1
            myLogger.error(msg)
    if (len(write_list)>0):
        try:
            collection_pcap.bulk_write(write_list,ordered=False)
        except Exception as e: 
            error=str(e)+':pcap_dir='+pcap_dir+':bin='+str(bin)+':error on bulk write to mongo'
            myLogger.error(error)
    
    
    elapsed_bulk=timeit.default_timer()-time_bulk
#    
    llp=json.dumps(outly_pairs)
    ld2=pd.DataFrame(loadings,index=df_feature_cols1)
    collection_bins.update_one({'pcap_dir':pcap_dir,'index':index},{'$set':{'outlying_pairs':llp,'PCs':ld2.to_json()}},upsert=False)
    msg='finished processing bin. Line513: directory= '+pcap_dir+':index='+str(index)
    myLogger.error(msg)
    
    
    first_ts+=time_interval
    
    
    
    





  