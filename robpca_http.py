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
import datetime

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
    if isinstance(obj, int):
            return str(obj)
    return obj

pcap_dir= 'maccdc2012_00003'

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
    dff.fillna(0.0,inplace=True)
    dff['jsd']=dff['jsd'].apply(float)
    
    return dff.jsd

def category_frequency_vectors(df2,feature_list):
    for ft in df2[feature_list]:
        column_name=ft+'_freq'
        df2[column_name]=0
        df2[column_name].apply(float)
        ft_freq=df2[ft].value_counts()/df2.shape[0]
        for category in ft_freq.index.values:
            df2.loc[df2[ft]==category,column_name]= ft_freq.loc[category] 
    return df2

def pair_category_frequency_vectors(df2,feature_list):
    for ft in df2[feature_list]:
        column_name=ft+'_pair_freq'
        if ft in list_features:
          
            df_fn=df2[ft].apply(pd.Series)
            df_fn=pd.DataFrame(df_fn[0])
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
        df2[column_name].apply(float)
        # # strip mime type list using .apply(pd.Series)
        df_fn=df2[fd].apply(pd.Series)
        if len(df_fn.columns)>1:
            df_fn=pd.DataFrame(df_fn[0])
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
            return [float(total_entropy),float(hex_entropy[0]),float(punctuation_entropy[0])]

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
#    if index<4:
#        first_ts+=time_interval
#        continue
   
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
    if df_cnt<20:
        first_ts+=time_interval
        continue
    
    username_flag='username' in df.columns
    category_features= [ ft  for ft in service_features_categories['http'] if ft in df.columns]
    df2=category_frequency_vectors(df.copy(),category_features)
    
    list_features_bin= [ ft  for ft in list_features if ft in df.columns]
    df2=list_features_frequency_vectors(df2,list_features_bin)          
    
    total_category_features=category_features+list_features_bin    
    
    # # prepping df2 pairwise feature columns
    pair_category_features=[x+'_pair_freq'  for x in total_category_features]
    for feature in pair_category_features:
            df2[feature]=0.0 
    # # prepping df2 pairwise jsd feature columns
    jsd_category_features=[x+'_jsd'  for x in total_category_features]
    for feature in jsd_category_features:
            df2[feature]=0.0
    
    
        
    # # grouping http flows by orig-resp pairs         
    gb=df2.groupby(['id_orig_h','id_resp_h'])
    dff=pd.DataFrame(index=gb.groups.keys())
    success=df2.loc[df2.status_code==200].shape[0]
    for pair in gb.groups:
        gtemp=gb.get_group(pair)
        if success>0:
            dff.loc[pair,'success_freq']=gtemp.loc[gtemp.status_code==200].shape[0]/success
        else:
            dff['success_freq']=float(0)
        dff.loc[pair,'attacks']=gtemp.loc[gtemp.attack_bool==True,:].shape[0]
        gtemp=pair_category_frequency_vectors(gtemp,total_category_features)
        for feature in total_category_features:
            gtemp[feature+'_pair_freq']=gtemp[feature+'_pair_freq']
            gtemp[feature+'_jsd']=jsd(gtemp[feature+'_freq'],gtemp[feature+'_pair_freq'])
        df2.loc[gtemp.index.values,'request_ts_diff_median']=gtemp.ts.diff().median()
        for ind in gtemp.index.values:
            for feature in total_category_features:
                fi=total_category_features.index(feature)
                df2.loc[ind,pair_category_features[fi]]=gtemp.loc[ind,pair_category_features[fi]]
                df2.loc[ind,jsd_category_features[fi]]=gtemp.loc[ind,jsd_category_features[fi]]

        
    
     # # sort the dataframe for the highest success_freq;
    
    dff=dff.sort_values(by='success_freq', ascending = False)
    # # total number of flows of pairs with success_freq less than 90% of all suceesses
    base_success_freq=0
    base_pairs=list()
    for nn in dff.index:
        base_success_freq+=float(dff.loc[dff.index==nn].success_freq)
        base_pairs.append(nn)
        if base_success_freq>0.9:
            break
    outly_pairs=list(set(gb.groups.keys())-set(base_pairs))
    msg='finish looking for bad flows. Line252: directory= '+pcap_dir+':index='+str(index)
    myLogger.error(msg)

    ind_uri=df2.loc[~df2.uri.isnull()].index.values
    uri_ent_vec=df2.loc[ind_uri,'uri'].apply(ltr_entropy).apply(pd.Series)
    
    df2['uri_entropy']=uri_ent_vec.loc[:,0]
    df2['uri_hexadecimal_entropy']=uri_ent_vec.loc[:,1]
    df2['uri_punctuation_entropy']=uri_ent_vec.loc[:,2]
    
    ind_post_content=df2.loc[~df2.post_content.isnull()].index.values
    post_ent_vec=df2.loc[ind_post_content,'post_content'].apply(ltr_entropy).apply(pd.Series)
    post_content_length_vec=df2.loc[ind_post_content,'post_content'].apply(len)
    
    df2['post_content_entropy']=post_ent_vec.loc[:,0]
    df2['post_content_hexadecimal_entropy']=post_ent_vec.loc[:,1]
    df2['post_content_punctuation_entropy']=post_ent_vec.loc[:,2]
    df2['post_content_length']=post_content_length_vec
    
    username_columns=['username_freq','username_pair_freq', 'username_jsd']
    all_feature_columns=['request_body_len', 'response_body_len', 
       'uri_length','request_ts_diff_median','post_content_length', 'method_freq',
       'status_code_freq', 'user_agent_freq', 
       'orig_mime_types_freq', 'resp_mime_types_freq', 'method_pair_freq',
       'status_code_pair_freq', 'user_agent_pair_freq', 'orig_mime_types_pair_freq',
       'resp_mime_types_pair_freq', 'method_jsd', 'status_code_jsd',
       'user_agent_jsd', 'orig_mime_types_jsd',
       'resp_mime_types_jsd', 'uri_entropy', 'uri_hexadecimal_entropy',
       'uri_punctuation_entropy', 'post_content_entropy',
       'post_content_hexadecimal_entropy',
       'post_content_punctuation_entropy']
    
    if username_flag:
        all_feature_columns=all_feature_columns+username_columns
    
    gbdict=dict(gb.groups)
    df_clean=df2.copy()
    for ppn in outly_pairs:
        # # dump all flows belonging to orig-resp pairs in outly_pairs from the overall bin flows
        df_clean=df_clean[~df_clean.index.isin(gbdict[ppn].values)]
    
    
    df_clean=df_clean.fillna(0)
    df3=df_clean[all_feature_columns]
    df3=df3.fillna(0)
    df3_n=(df3-df3.mean() )/df3.std(ddof=0)
    df3_n=df3_n.fillna(0)
    print('sugar')
    df_mat=df3_n.as_matrix()
    
    msg='start first robpca. Line296: directory= '+pcap_dir+':index='+str(index)
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
    
   

    
    # #  compute the PCA sub-space covariance matrix
    num_e_vals=e_vals.shape[0]
    lambda_mat=e_vals*np.identity(num_e_vals)    
    pca_cov=(loadings.dot(lambda_mat)).dot(loadings.T)
    # # standardized Data Frame- robust PCA center multiplied by the PCA loadings, will give us our PCA scores
    df2['SD']=SD
    df2['SD_anomaly']=False
    df2.loc[df2.SD>SD_th[0],'SD_anomaly']=True
    df2['OD']=OD
    df2['OD_anomaly']=False
    df2.loc[df2.OD>SD_th[0],'OD_anomaly']=True
    # # find the most influential feature for anomalous SD values
    feat_vec_sd=which_feature_SD(df3_n.loc[df2.SD>SD_th[0],:],pca_cov)
    df2['SD_feature']=0.0
    df2.loc[df2.SD>SD_th[0],'SD_feature']=feat_vec_sd
    # # find the most influential feature for anomalous OD values
    feat_vec_od=which_feature_OD(df3_n.loc[df2.OD>OD_th[0],:])
    df2['OD_feature']=0.0
    df2.loc[df2.OD>OD_th[0],'OD_feature']=feat_vec_od
    
    # # find df_clean index that was used for mcd
    mcd_index=df3_n.iloc[H1==1].index.values
    
    df2["mcd"]=False
    df2.loc[df3_n.iloc[H1==1].index.values,'mcd']=True
    
    
    msg='start single line write to mongo . Line346: directory= '+pcap_dir+':index='+str(index)
    myLogger.error(msg)
    
 
    bin_lst=list(df._id)
        
    df.to_csv(str('df_'+pcap_dir+'_http_'+'bin_'+str(index)+'.csv'))
    service_coll.update_many({'_id': {'$in': bin_lst}},{'$set':{'bin':index}})

    msg='start bulk write to mongo. Line355: directory= '+pcap_dir+'_http'+':index='+str(index)
    myLogger.error(msg)
    
    df2=df2.fillna(0.0)  
   
    from pymongo import UpdateOne
    time_bulk=timeit.default_timer()
    
    bulk=service_coll.initialize_unordered_bulk_op()
    d=0
    write_list=list()
    for idd in bin_lst:
        write_list.append(UpdateOne({'_id':idd},{'$set':{'request_ts_diff_median':df2.loc[df2._id==idd,'request_ts_diff_median'].values[0]
                                                     ,'post_content_length':df2.loc[df2._id==idd,'post_content_length'].values[0]
                                                    ,'method_freq':df2.loc[df2._id==idd,'method_freq'].values[0]
                                                    ,'status_code_freq':df2.loc[df2._id==idd,'status_code_freq'].values[0]
                                                    ,'user_agent_freq':df2.loc[df2._id==idd,'user_agent_freq'].values[0]
                                                    #,'username_freq':df2.loc[df2._id==idd,'username_freq'].values[0]
                                                    ,'orig_mime_types_freq':df2.loc[df2._id==idd,'orig_mime_types_freq'].values[0]
                                                    ,'mcd':json_bool(df2.loc[df2._id==idd,'mcd'].values[0])
                                                    ,'method_pair_freq':df2.loc[df2._id==idd,'method_pair_freq'].values[0]
                                                    ,'status_code_pair_freq':df2.loc[df2._id==idd,'status_code_pair_freq'].values[0]
                                                    ,'user_agent_pair_freq':df2.loc[df2._id==idd,'user_agent_pair_freq'].values[0]
                                                    #,'username_pair_freq':df2.loc[df2._id==idd,'username_pair_freq'].values[0]
                                                    ,'orig_mime_types_pair_freq':df2.loc[df2._id==idd,'orig_mime_types_pair_freq'].values[0]
                                                    ,'resp_mime_types_pair_freq':df2.loc[df2._id==idd,'resp_mime_types_pair_freq'].values[0]
                                                    ,'method_jsd':df2.loc[df2._id==idd, 'method_jsd'].values[0]
                                                    ,'status_code_jsd':df2.loc[df2._id==idd,'status_code_jsd'].values[0]
                                                    ,'user_agent_jsd':df2.loc[df2._id==idd,'user_agent_jsd'].values[0]
                                                    #,'username_jsd':df2.loc[df2._id==idd,'username_jsd'].values[0]
                                                    ,'orig_mime_types_jsd':df2.loc[df2._id==idd,'orig_mime_types_jsd'].values[0]
                                                    ,'resp_mime_types_jsd':df2.loc[df2._id==idd,'resp_mime_types_jsd'].values[0]
                                                    ,'uri_entropy':df2.loc[df2._id==idd,'uri_entropy'].values[0]
                                                    ,'uri_hexadecimal_entropy':df2.loc[df2._id==idd,'uri_hexadecimal_entropy'].values[0]
                                                    ,'uri_punctuation_entropy':df2.loc[df2._id==idd,'uri_punctuation_entropy'].values[0]
                                                    ,'post_content_entropy':df2.loc[df2._id==idd,'post_content_entropy'].values[0]
                                                    ,'post_content_hexadecimal_entropy':df2.loc[df2._id==idd,'post_content_hexadecimal_entropy'].values[0]
                                                    ,'post_content_punctuation_entropy':df2.loc[df2._id==idd,'post_content_punctuation_entropy'].values[0]
                                                    ,'SD':json_bool(df2.loc[df2._id==idd,'SD'].values[0])
                                                    ,'SD_anomaly':json_bool(df2.loc[df2._id==idd,'SD_anomaly'].values[0])
                                                    ,'SD_feature':json_bool(df2.loc[df2._id==idd,'SD_feature'].values[0])
                                                    ,'OD':json_bool(df2.loc[df2._id==idd,'OD'].values[0])
                                                    ,'OD_anomaly':json_bool(df2.loc[df2._id==idd,'OD_anomaly'].values[0])
                                                    ,'OD_feature':json_bool(df2.loc[df2._id==idd,'OD_feature'].values[0])
                                                    }})
    )
    
        if (len(write_list)%500==0):
            try:
                service_coll.bulk_write(write_list,ordered=False)
            except Exception as e: 
                error=str(e)+':pcap_dir='+pcap_dir+':bin='+str(bin)+':batch='+str(d)+':error on bulk write to mongo'
                myLogger.error(error)
            write_list=list() 
            msg='wrote bulk to mongo. Line520: directory= '+pcap_dir+':index='+str(index)+':batch='+str(d)+': write_list size:'+str(len(write_list))
            d+=1
            myLogger.error(msg)
    if (len(write_list)>0):
        try:
            service_coll.bulk_write(write_list,ordered=False)
        except Exception as e: 
            error=str(e)+':pcap_dir='+pcap_dir+':bin='+str(bin)+':error on bulk write to mongo'
            myLogger.error(error)
    
    elapsed_bulk=timeit.default_timer()-time_bulk
    
    ld2=pd.DataFrame(loadings,index=all_feature_columns)
    collection_bins.update_one({'pcap_dir':pcap_dir,'index':index},{'$set':{'HTTP_PCs':ld2.to_json(),'HTTP_SD_threshold':SD_th[0],'HTTP_OD_threshold':OD_th[0]}},upsert=False)
    msg='finished processing bin. Line421: directory= '+pcap_dir+':index='+str(index)
    myLogger.error(msg)
    
    
    first_ts+=time_interval