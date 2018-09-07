# -*- coding: utf-8 -*-


import pandas as pd
import math
import numpy as np
import scipy as sci
import json
import pymongo
import os
import csv

import rpy2
from rpy2.robjects.packages import importr
import rpy2.robjects as robjects
import rpy2.robjects.numpy2ri
from pandas.io.json import json_normalize

import logging
import time
import datetime
import matplotlib.pyplot as plt
import seaborn as sns
sns.set(style="white", color_codes=True, context="talk")
import gc

home_dir='D:\\personal\\msc\\maccdc_2012\\'


logFormt='%(asctime)s: %(filename)s: %(lineno)d: %(message)s'
fh=logging.FileHandler(filename=home_dir+'error2.log')
fh.setLevel(logging.DEBUG)
frmt=logging.Formatter(fmt=logFormt)
fh.setFormatter(frmt)
myLogger = logging.getLogger('maccdc')
myLogger.setLevel(logging.DEBUG)
myLogger.addHandler(fh)


wpi_dir='wpi\\'

class JSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, 'to_json'):
            return obj.to_json(orient='records')
        if isinstance(obj, bool):
            return str(obj).lower()
        if isinstance(obj,np.integer):
            return int(obj)
        return json.JSONEncoder.default(self, obj)

def default(o):
     if isinstance(o, np.integer): return int(o)

def mongo_json(mydict):
    mydict2=mydict.copy()
    for key,value in mydict.items():
           kk=key.split('.')
           kd=''
           if len(kk)>1:
               for k in kk:
                   kd=kd+k+'_'
               kd=kd[:-1]
               mydict2[kd]=mydict2.pop(key)
           
    return mydict2
               

def   time_to_ts(row_ts):  
      strd=row_ts[:-2]
      dt=datetime.datetime.strptime(strd,'%m/%d/%y-%H:%M:%S.%f')
      snrt_ts = dt.timestamp()
      snrt_ts=snrt_ts+7200
      return float(snrt_ts)



client = pymongo.MongoClient('localhost')
db = client['local']

def get_db():
    return db

dff=pd.DataFrame()
dl=next(os.walk(home_dir+wpi_dir))[2]
dl.sort()
remove=[]

inside_outside_flag='outside'
train_test_flag='train'


important_ports=[80,139,445,137,135,111,23,21,22,53]


snrt_frmt=['timestamp','sig_generator','sig_id','sig_rev','msg','proto','src','srcport','dst','dstport','ethsrc','ethdst','ethlen','tcpflags','tcpseq','tcpack','tcplen','tcpwindow','ttl','tos','id','dgmlen','iplen','icmptype','icmpcode','icmpid','icmpseq']


inside_train_coll=get_db()['maccdc2012_00002_train']
#inside_train_coll.insert_many(df_dict2)

#with open(home_dir+'\\maccdc2012_00002\\alert.csv' ,'r') as snort_f:
#    snort_lines=list()
#    reader = csv.reader(snort_f)
#    for line in reader:
#        line_dict=dict(zip(snrt_frmt,line))
#        line_dict['timestamp']=time_to_ts(line_dict['timestamp'])
#        snort_lines.append(line_dict)
#
#for counter, dd in enumerate(snort_lines): 
#    if (dd['proto']=='TCP')|(dd['proto']=='UDP'):
#        snort_tuple=(dd['timestamp'],dd['src'],int(dd['srcport']),dd['dst'],int(dd['dstport']))
#        snort_docs=inside_train_coll.find({'timestamp':snort_tuple[0],'src_ip_addr':snort_tuple[1],'src_port':snort_tuple[2],'dst_ip_addr':snort_tuple[3],'dst_port':snort_tuple[4]})
#    else:
#        snort_tuple=(dd['timestamp'],dd['src'],dd['dst'])
#        snort_docs=inside_train_coll.find({'timestamp':snort_tuple[0],'src_ip_addr':snort_tuple[1],'dst_ip_addr':snort_tuple[2],'ip_proto':dd['proto'].lower()})
#
#    snort_df=pd.DataFrame(list(snort_docs))
#    if snort_df.shape[0]>0:
#        inside_train_coll.update_one({'_id':snort_df.loc[0,'_id']},{'$set':{'attack':1}})
#    else:
#        msg='missed snort signature:'+str(snort_lines.index(dd))
#        myLogger.error(msg)
#        break

#last_ts=snort_lines[counter-1]['timestamp']
first_doc= inside_train_coll.find(sort=[('_id',1)],limit=1)
first_line=pd.DataFrame(list(first_doc)).to_dict(orient='records')
first_ts=first_line[0]['timestamp']

#doc_list= inside_train_coll.find()
doc_list=inside_train_coll.find({'timestamp':{'$lte':first_ts+15}})
conn_df_db=pd.DataFrame(list(doc_list))
conn_df_db=conn_df_db.fillna(0)
conn_df_shape=conn_df_db.shape[0]
train=math.floor(2*conn_df_shape/3)

no_columns=['_id','timestamp','src_ip_addr','dst_ip_addr','src_port','dst_port','ip_proto','attack','pkt_len']
df_mat=conn_df_db.loc[:,conn_df_db.columns.difference(no_columns)].as_matrix()
msg='start first rpca. Line140'
myLogger.error(msg)

rpy2.robjects.numpy2ri.activate()
rpca_pkg=importr("rpca")
import rpy2.rinterface as rinterface
rinterface.initr()
df_mat_r=robjects.r.matrix(df_mat,nrow=df_mat.shape[0])

#del(conn_df_db)
gc.collect()
#rpca=rpca_pkg.rpca(df_mat,**{'lambda': 0.1})
#L_matrix=np.array(rpca[0])
#S_matrix=np.array(rpca[1])
#L_svd=np.array(rpca[2])
#eigen_values=np.array(L_svd[0])
#eigen_vectors=pd.DataFrame(np.array(L_svd[2]),columns=conn_df_db.columns.difference(no_columns))
#eigen_vectors=eigen_vectors.T
#S_mat_df=pd.DataFrame(S_matrix,columns=conn_df_db.columns.difference(no_columns))
#    
#df_target=pd.DataFrame(index=conn_df_db.index)
#df_target['attack']=conn_df_db.attack
#df_target['max_val']=S_mat_df.loc[:,:].abs().max(axis=1)
#df_target['idxmax']=S_mat_df.loc[:,:].abs().idxmax(axis=1)    
#
#fig, axes = plt.subplots(1, 1, sharex=True, sharey=True,figsize=(24,10))
##sns.barplot(x=df_target.index.values,y=df_target.max_val.values,hue=df_target.attack,ax=axes)
##axes.bar(df_target.index.values,df_target.max_val.values)
##plt.show()
#
#groups = df_target.groupby('attack')
#for name, group in groups:   
#    if name==False:
#        axes.stem(group.index.values,group.max_val.values,linefmt='C1-',markerfmt='C1+',label='no_attack')
#    else:
#        axes.stem(group.index.values,group.max_val.values,linefmt='C2-',markerfmt='C2^',label='attack')
#
#plt.legend(loc=2)
#plt.show()

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
    s_time=time.time()
    rpca=rpca_pkg.rpca(df_mat,**{'lambda': ll})
    e_time=time.time()
    call_time=int(e_time-s_time)
    call_time_fmt=str(datetime.timedelta(seconds=call_time))
    L_matrix=np.array(rpca[0])
    S_matrix=np.array(rpca[1])
    L_svd=np.array(rpca[2])
    eigen_values=np.array(L_svd[0])
    eigen_vectors=pd.DataFrame(np.array(L_svd[2]),columns=conn_df_db.columns.difference(no_columns))
    eigen_vectors=eigen_vectors.T
    S_mat_df=pd.DataFrame(S_matrix,columns=conn_df_db.columns.difference(no_columns))
    
    
    df_target=pd.DataFrame(index=conn_df_db.index)
    df_target['attack']=conn_df_db.attack
    df_target['max_val']=S_mat_df.loc[:,:].abs().max(axis=1)
    df_target['idxmax']=S_mat_df.loc[:,:].abs().idxmax(axis=1)  
    tpr,fpr,_ = roc_curve(df_target.attack.apply(lambda x:1 if x==True else 0),df_target.max_val.apply(lambda x:1 if (x-alpha)>0 else 0 ))
    roc_auc = roc_auc_score(df_target.attack.apply(lambda x:1 if x==True else 0),df_target.max_val.apply(lambda x:1 if (x-alpha)>0 else 0 ))
    auc_list.append(roc_auc)
    per,rec,_pr=p,r,_ = precision_recall_curve(df_target.attack.apply(lambda x:1 if x==True else 0),df_target.max_val.apply(lambda x:1 if (x-alpha)>0 else 0 ))
    f1_scr= f1_score(df_target.attack.apply(lambda x:1 if x==True else 0),df_target.max_val.apply(lambda x:1 if (x-alpha)>0 else 0 ))
    f1_list.append(f1_scr)
    ax_roc.plot(tpr,fpr,c=k,label=(ll,round(roc_auc,2)))
    ax_pr.plot(rec,per,c=k,label=(ll,round(f1_scr,2)))
    
ax_roc.legend(loc='lower left')
ax_pr.legend(loc='lower left')
plt.show()
fig_plot.savefig(inside_outside_flag+'_'+train_test_flag+'_roc.png')

crit_lambda=lambda_c[f1_list.index(np.max(f1_list))]

print('motek')