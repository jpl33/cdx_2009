import pandas as pd
import math
import numpy as np
import scipy as sci

import json
import pymongo

import rpy2
from rpy2.robjects.packages import importr
import rpy2.robjects.numpy2ri
import string
import re
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

def category_frequency_vectors(df2,feature_list):
    for ft in df2[feature_list]:
        column_name=ft+'_freq'
        df2[column_name]=0
        ft_freq=df2[ft].value_counts()/df2.shape[0]
        for category in ft_freq.index.values:
            df2.loc[df2[ft]==category,column_name]= ft_freq.loc[category] 
    return df2

def pair_category_frequency_vectors(df2,feature_list):
    for ft in df2[feature_list]:
        column_name=ft+'_pair_freq'
        if ft in list_features:
          
            df_fn=df2[ft].apply(pd.Series)
            df_fn.columns=[ft]
            # # select only valid mime_types
            df_fn2=df_fn.loc[~df_fn[ft].isnull()]
            ft_freq=df_fn2[ft].value_counts()/df_fn2.shape[0]
            for category in ft_freq.index.values:
                df2.loc[df_fn.loc[df_fn[ft]==category].index.values,column_name]= ft_freq.loc[category] 
        else:
            ft_freq=df2[ft].value_counts()/df2.shape[0]
        for category in ft_freq.index.values:
            df2.loc[df2[ft]==category,column_name]= ft_freq.loc[category] 
    return df2




def list_features_frequency_vectors(df2,list_features):
    for fd in list_features:
        column_name=fd+'_freq'
        df2[column_name]=0
        # # strip mime type list using .apply(pd.Series)
        df_fn=df2[fd].apply(pd.Series)
        df_fn.columns=[fd]
        # # select only valid mime_types
        df_fn2=df_fn.loc[~df_fn[fd].isnull()]
        fd_freq=df_fn2[fd].value_counts()/df_fn2.shape[0]
        for nn in fd_freq.index.values:
            # # take the indexes of df_fn where its value is that of fd_freq index,
            # # and use the indexes to set the correct cells in df2
            df2.loc[df_fn.loc[df_fn[fd]==nn].index.values,column_name]=fd_freq.loc[nn]
    return df2

def ltr_entropy(string_mine):
        "Calculates the Shannon entropy of a string"
        # get probability of chars in string
        dict_str=dict.fromkeys(list(string_mine))
        
        prob = [ float(string_mine.count(c)) / len(string_mine) for c in dict_str]

        # calculate the entropy
        entropy = [ p * math.log(p) / math.log(2.0) for p in prob ]
        
        dict_entropy=dict(zip(dict_str,entropy))
        
        hex_entropy=[dict_entropy[x] if x not in string.printable else 0 for x in dict_entropy]
        
        punctuation_entropy=[dict_entropy[x] if x  in string.punctuation else 0 for x in dict_entropy]
        
        total_entropy=-sum(entropy)
        if total_entropy>0:
            return [total_entropy,-sum(hex_entropy)/total_entropy,-sum(punctuation_entropy)/total_entropy]
        else:
            return [total_entropy,hex_entropy[0],punctuation_entropy[0]]

def is_numeric_uri(uri_str):
    re1=re.findall('\.[0-9]{1,3}',uri_str)
    
    return (len(re1)==3)

df_feature_cols2=['duration','orig_bytes','resp_bytes','orig_pkts','resp_pkts','orig_pkts_intr','cumultv_pkt_count','orig_pkts_size','serv_freq','history_freq','conn_state_freq']

service_features={'http':['method','orig_mime_types', 'referrer',
       'request_body_len', 'resp_mime_types',
       'response_body_len', 'status_code', 'status_msg', 'tags',
       'trans_depth', 'ts', 'uid', 'uri', 'uri_length', 'user_agent',
       'username', 'version']}
list_features=['orig_mime_types','resp_mime_types']
content_features={'http':['uri','post_content']}
service_features_categories={'http':['method' 
       , 'status_code', 'user_agent',
       'username']}
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
    service='http'
    service_coll=get_db()[pcap_dir+'_'+service]
    
    if index==intervals-1:
        doc_tt=service_coll.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lte':last_ts}}]})
    else:
        # # find from the timestamp, up to the pre-set time interval size
        doc_tt=service_coll.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':first_ts+time_interval}}]})

    df =  pd.DataFrame(list(doc_tt)) 
    # # number of flows in bin
    df_cnt=df.shape[0]
       
    
    df2=category_frequency_vectors(df.copy(),service_features_categories['http'])
    

    df2=list_features_frequency_vectors(df2,list_features)          
    
    total_category_features=service_features_categories['http']+list_features    
    
    # # prepping df2 pairwise feature columns
    pair_category_features=[x+'_pair_freq'  for x in total_category_features]
    for feature in pair_category_features:
            df2[feature]=0 
    # # prepping df2 pairwise jsd feature columns
    jsd_category_features=[x+'_jsd'  for x in total_category_features]
    for feature in jsd_category_features:
            df2[feature]=0 
            
    # # grouping http flows by orig-resp pairs         
    gb=df2.groupby(['id_orig_h','id_resp_h'])
    for pair in gb.groups:
        gtemp=gb.get_group(pair)
        gtemp=pair_category_frequency_vectors(gtemp,total_category_features)
        for feature in total_category_features:
            gtemp[feature+'_pair_freq']=gtemp[feature+'_pair_freq']
            gtemp[feature+'_jsd']=jsd(gtemp[feature+'_freq'],gtemp[feature+'_pair_freq'])
        
        for ind in gtemp.index.values:
            for feature in service_features_categories['http']:
                fi=service_features_categories['http'].index(feature)
                df2.loc[ind,pair_category_features[fi]]=gtemp.loc[ind,pair_category_features[fi]]
                df2.loc[ind,jsd_category_features[fi]]=gtemp.loc[ind,jsd_category_features[fi]]

        

    
    uri_ent_vec=df2.uri.apply(ltr_entropy).apply(pd.Series)
    
    df2['uri_entropy']=uri_ent_vec.loc[:,0]
    df2['uri_hexadecimal_entropy']=uri_ent_vec.loc[:,1]
    df2['uri_punctuation_entropy']=uri_ent_vec.loc[:,2]
    
    ind_post_content=df2.loc[~df2.post_content.isnull()].index.values
    post_ent_vec=df2.loc[ind_post_content,'post_content'].apply(ltr_entropy).apply(pd.Series)
        
    df2['post_content_entropy']=post_ent_vec.loc[:,0]
    df2['post_content_hexadecimal_entropy']=post_ent_vec.loc[:,1]
    df2['post_content_punctuation_entropy']=post_ent_vec.loc[:,2]
    
    
    df2.fillna()
    df2_n=(df2-df2.mean() )/df2.std(ddof=0)
    