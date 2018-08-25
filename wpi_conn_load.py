# -*- coding: utf-8 -*-


import pandas as pd
import math
import numpy as np
import scipy as sci
import json
import pymongo
import os

import rpy2
from rpy2.robjects.packages import importr
import rpy2.robjects.numpy2ri
from pandas.io.json import json_normalize

import logging
import time
import matplotlib.pyplot as plt
import seaborn as sns
sns.set(style="white", color_codes=True, context="talk")


home_dir='D:\\personal\\msc\\maccdc_2012\\'


logFormt='%(asctime)s: %(filename)s: %(lineno)d: %(message)s'
fh=logging.FileHandler(filename=home_dir+'error.log')
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
               




client = pymongo.MongoClient('localhost')
db = client['local']

def get_db():
    return db

dff=pd.DataFrame()
dl=next(os.walk(home_dir+wpi_dir))[2]
dl.sort()
remove=[]
for d in dl:
    if ( not d.startswith(('inside'))  ):
        remove.append(d)
prcs_file= open('processed_wpi_files.txt', 'r+')
for l in prcs_file.readlines():
    l=l.split("\n")[0]
    if len(l)>1:
        remove.append(l)
for r in remove:
    dl.remove(r)

important_ports=[80,139,445,137,135,111,23,21,22,53]

   
inside_train_coll=get_db()['inside_train']
#inside_train_coll.insert_many(df_dict2)


doc_list= inside_train_coll.find()
conn_df_db=pd.DataFrame(list(doc_list))


no_columns=['_id','timestamp','src_ip_addr','dst_ip_addr','src_port','dst_port','ip_proto','attack','pkt_len']
df_mat=conn_df_db.loc[:,conn_df_db.columns.difference(no_columns)].as_matrix()

msg='start first rpca. Line104'
myLogger.error(msg)

rpy2.robjects.numpy2ri.activate()
rpca_pkg=importr("rpca")
rpca=rpca_pkg.rpca(df_mat,**{'lambda': 0.3})
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

fig, axes = plt.subplots(1, 1, sharex=True, sharey=True,figsize=(24,10))
#sns.barplot(x=df_target.index.values,y=df_target.max_val.values,hue=df_target.attack,ax=axes)
#axes.bar(df_target.index.values,df_target.max_val.values)
#plt.show()

groups = df_target.groupby('attack')
for name, group in groups:   
    if name==False:
        axes.stem(group.index.values,group.max_val.values,linefmt='C1-',markerfmt='C1+',label='no_attack')
    else:
        axes.stem(group.index.values,group.max_val.values,linefmt='C2-',markerfmt='C2^',label='attack')

plt.legend(loc=2)
plt.show()

    
print('motek')