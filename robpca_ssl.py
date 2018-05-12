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
    service='ssl'
    service_coll=get_db()[pcap_dir+'_'+service]
    
    if index==intervals-1:
        doc_tt=service_coll.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lte':last_ts}}]})
    else:
        # # find from the timestamp, up to the pre-set time interval size
        doc_tt=service_coll.find({'$and':[{'ts':{'$gte':first_ts}},{'ts':{'$lt':first_ts+time_interval}}]})

    df =  pd.DataFrame(list(doc_tt)) 
    # # number of flows in bin
    df_cnt=df.shape[0]
       
   
    df['anomaly']=False
    df2=df.loc[~df.issuer.isnull()]
    # # grouping dns flows by orig-resp pairs         
    gb1=df2.groupby(['id_resp_h'])
    for resp in gb1.groups:
        gtemp=gb1.get_group(resp)
        gb2=gtemp.groupby(['validation_status','issuer'])
        if len(gb2.groups)>1:
            dict_key_lst=[x for x in gb2.groups.keys() if 'self signed certificate' in x]
            if len(dict_key_lst)>0:
                gtemp2=gb2.get_group((dict_key_lst[0][0],dict_key_lst[0][1]))
                df.loc[gtemp2.index.values,'anomaly']=True
                
            
    
    
    
    msg='start single line write to mongo . Line129: directory= '+pcap_dir+':index='+str(index)
    myLogger.error(msg)
    
 
    bin_lst=list(df2._id)
        
    #df2.to_csv(str('df_'+pcap_dir+'_ssl_'+'bin_'+str(index)+'.csv'))
    service_coll.update_many({'_id': {'$in': bin_lst}},{'$set':{'bin':index}})

    msg='start bulk write to mongo. Line246: directory= '+pcap_dir+'_ssl'+':index='+str(index)
    myLogger.error(msg)
    
    df2=df2.fillna(0)  
   
    from pymongo import UpdateOne
    time_bulk=timeit.default_timer()
    bulk=service_coll.initialize_unordered_bulk_op()
    d=0
    write_list=list()
    for idd in bin_lst:
        write_list.append(UpdateOne({'_id':idd},{'$set':{'anomaly':json_bool(df2.loc[df2._id==idd,'anomaly'].values[0])}}))
    
    
        if (len(write_list)%500==0):
            try:
                service_coll.bulk_write(write_list,ordered=False)
            except Exception as e: 
                error=str(e)+':pcap_dir='+pcap_dir+':bin='+str(bin)+':batch='+str(d)+':error on bulk write to mongo'
                myLogger.error(error)
            write_list=list() 
            msg='wrote bulk to mongo. Line159: directory= '+pcap_dir+':index='+str(index)+':batch='+str(d)+': write_list size:'+str(len(write_list))
            d+=1
            myLogger.error(msg)
    if (len(write_list)>0):
        try:
            service_coll.bulk_write(write_list,ordered=False)
        except Exception as e: 
            error=str(e)+':pcap_dir='+pcap_dir+':bin='+str(bin)+':error on bulk write to mongo'
            myLogger.error(error)
    
    elapsed_bulk=timeit.default_timer()-time_bulk
    
    msg='finished processing bin. Line171: directory= '+pcap_dir+':index='+str(index)
    myLogger.error(msg)
    
    
    first_ts+=time_interval