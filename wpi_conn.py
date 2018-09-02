# -*- coding: utf-8 -*-


import pandas as pd
import math
import numpy as np
import scipy as sci
import json
import pymongo
import os
import itertools

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
inside_outside_flag='outside'
train_test_flag='train'
for d in dl:
    if ( not d.startswith('maccdc2012')  ):
        remove.append(d)
#prcs_file= open('processed_wpi_files.txt', 'r+')
#for l in prcs_file.readlines():
#    l=l.split("\n")[0]
#    if len(l)>1:
#        remove.append(l)
for r in remove:
    dl.remove(r)

important_ports=[80,139,445,137,135,111,23,21,22,53]

conn_df_db=pd.DataFrame()

with open(home_dir+'\\maccdc2012_00001\\alert.csv' ,'r') as snort_f:
    snort_lines=snort_f.readlines()
    
first_ts=float(0)
old_ts=0
line_num=1
time_interval=180

for fl in dl: 
    with open(home_dir+wpi_dir +fl,'r') as wpi_f:
        with open(home_dir+wpi_dir +'tail_'+str(dl.index(fl)+1)+'.json','r') as tail_f:
            last_line=tail_f.readline()
        last_line=json.loads(last_line)
        last_ts=float(last_line['layers']['frame']['frame_frame_time_epoch'])
        
        for line in itertools.islice(wpi_f,1,2):
            first_line=json.loads(line)
            first_ts=float(first_line['layers']['frame']['frame_frame_time_epoch'])
            ts=first_ts
        intervals=math.ceil((last_ts-first_ts)/time_interval)
        for index in range(intervals):
            file_df=pd.DataFrame()
            for line in itertools.islice(wpi_f,line_num,None,2):
                if ((index<intervals)&(ts>first_ts+1)) | (not line) :
                    file_df=file_df.set_index(np.arange(file_df.shape[0]))
                    file_df=file_df.loc[:file_df.shape[0]-2,:]
                    conn_df=pd.DataFrame(index=file_df.index.values)
                    file_df=file_df.fillna(0)
                    src_ip_vec=file_df.loc[:,'layers.ip.ip_ip_src']
                    dst_ip_vec=file_df.loc[:,'layers.ip.ip_ip_dst']
                    ts_vec=file_df.loc[:,'layers.frame.frame_frame_time_epoch']
                    ip_proto_vec=file_df.loc[:,'layers.ip.ip_ip_proto']
                    ip_proto_dict={0:'other',1:'icmp',17:'udp',6:'tcp',88:'other'}    
                    udp_ll=[c for c in file_df.columns if 'udp' in c]
                    tcp_ll=[c for c in file_df.columns if 'tcp' in c]
                    rpc_ll=[c for c in file_df.columns if 'rpc' in c]
                    
                    if len(udp_ll)>0:
                        src_port_udp_vec=file_df.loc[:,'layers.udp.udp_udp_srcport']
                        dst_port_udp_vec=file_df.loc[:,'layers.udp.udp_udp_dstport']
                        s1=file_df['layers.udp.udp_udp_srcport'].astype(float)
                        is_portmap_vec=s1.mask(s1!=111,file_df['layers.udp.udp_udp_dstport'].astype(float))
                        is_portmap_vec=pd.DataFrame(is_portmap_vec.fillna(0).apply(lambda x:1 if x==111 else 0).astype(int).values,columns=['is_portmap'] )
                    else:
                        src_port_udp_vec=pd.Series(np.repeat(0,file_df.shape[0]))
                        dst_port_udp_vec=pd.Series(np.repeat(0,file_df.shape[0]))
                        is_portmap_vec=pd.DataFrame(np.repeat(0,file_df.shape[0]).astype(int),columns=['is_portmap'])
                        
#                    if len(rpc_ll)>0:
#                        is_sadmind_vec=pd.DataFrame(file_df['layers.rpc.rpc_rpc_program'].fillna(0).astype(int).apply(lambda x: 1 if x ==100232 else 0).astype(int).values,columns=['is_sadmind'])
#                    else:
#                        is_sadmind_vec=pd.DataFrame(np.repeat(0,file_df.shape[0]).astype(int),columns=['is_sadmind'])
#                        
                    if len(tcp_ll)>0:
                        src_port_tcp_vec=file_df.loc[:,'layers.tcp.tcp_tcp_srcport']
                        dst_port_tcp_vec=file_df.loc[:,'layers.tcp.tcp_tcp_dstport']
                        is_telnet_vec=pd.DataFrame(src_port_tcp_vec.mask(src_port_tcp_vec!=23,dst_port_tcp_vec).fillna(0).astype(int).apply(lambda x: 1 if x ==23 else 0).astype(int).values,columns=['is_telnet'])
                        is_ftp_vec=pd.DataFrame(src_port_tcp_vec.mask(src_port_tcp_vec!=21,dst_port_tcp_vec).fillna(0).astype(int).apply(lambda x: 1 if x ==21 else 0).astype(int).values,columns=['is_ftp'])
                        is_http_vec=pd.DataFrame(src_port_tcp_vec.mask(src_port_tcp_vec!=80,dst_port_tcp_vec).fillna(0).astype(int).apply(lambda x: 1 if x ==80 else 0).astype(int).values,columns=['is_http'])
                    else:
                        src_port_tcp_vec=pd.Series(np.repeat(0,file_df.shape[0]))
                        dst_port_tcp_vec=pd.Series(np.repeat(0,file_df.shape[0]))
                        is_telnet_vec=pd.DataFrame(np.repeat(0,file_df.shape[0]).astype(int),columns=['is_telnet'])
                        is_ftp_vec=pd.DataFrame(np.repeat(0,file_df.shape[0]).astype(int),columns=['is_ftp'])
                        is_http_vec=pd.DataFrame(np.repeat(0,file_df.shape[0]).astype(int),columns=['is_http'])
                    
                    src_port_vec=src_port_udp_vec.combine(src_port_tcp_vec,lambda x1, x2: x2 if pd.isnull(x1) else x1).fillna(0).astype(int)
                    dst_port_vec=dst_port_udp_vec.combine(dst_port_tcp_vec,lambda x1, x2: x2 if pd.isnull(x1) else x1).fillna(0).astype(int)
                    conn_df['src_ip_addr']=src_ip_vec
                    conn_df['dst_ip_addr']=dst_ip_vec
                    conn_df['ip_proto']=pd.Series(ip_proto_vec).astype(int).apply(lambda x: ip_proto_dict[x])
                    conn_df['src_port']=src_port_vec.astype(int)
                    conn_df['dst_port']=dst_port_vec.astype(int)
                    conn_df['timestamp']=ts_vec
                    conn_df['bin']=index
            
                    
                    important_src_port_vec=conn_df.src_port.astype(int).apply(lambda x: 1 if x in important_ports else 0).astype(int)
                    important_dst_port_vec=conn_df.dst_port.astype(int).apply(lambda x: 1 if x in important_ports else 0).astype(int)
                    high_src_port_vec=conn_df.src_port.astype(int).apply(lambda x: 1 if x >1024 else 0).astype(int)
                    high_dst_port_vec=conn_df.dst_port.astype(int).apply(lambda x: 1 if x >1024 else 0).astype(int)
                    missing_src_port_vec=pd.DataFrame(conn_df.src_port.astype(int).apply(lambda x: 1 if x ==0 else 0).astype(int).values,columns=['missing_src_port'])
                    missing_dst_port_vec=pd.DataFrame(conn_df.dst_port.astype(int).apply(lambda x: 1 if x ==0 else 0).astype(int).values,columns=['missing_dst_port'])
                    is_icmp_vec=pd.DataFrame(conn_df.ip_proto.apply(lambda x: 1 if x =='icmp' else 0).astype(int).values,columns=['is_icmp'])
                    pkt_len_vec=pd.DataFrame(file_df['layers.ip.ip_ip_len'].astype(float).values,columns=['pkt_len'])
                    
                    df_dummies_1=pd.get_dummies(conn_df[['src_ip_addr','dst_ip_addr']])
                    df_dummies_2=pd.get_dummies(important_src_port_vec,prefix='important_src_port')
                    df_dummies_3=pd.get_dummies(important_dst_port_vec,prefix='important_dst_port')
                    df_dummies_4=pd.get_dummies(high_src_port_vec,prefix='high_src_port')
                    df_dummies_5=pd.get_dummies(high_dst_port_vec,prefix='high_dst_port')
                    features=[conn_df,df_dummies_1,df_dummies_2,df_dummies_3,df_dummies_4,df_dummies_5,missing_src_port_vec,missing_dst_port_vec,is_icmp_vec,is_portmap_vec,is_telnet_vec,is_ftp_vec,is_http_vec,pkt_len_vec]#,is_sadmind_vec
                    conn_df=pd.concat(features,axis=1)
                    conn_df_db=conn_df_db.append(conn_df,ignore_index=True)
                    first_ts+=1
                    break
                
                line_data=json.loads(line)
                ts=float(line_data['layers']['frame']['frame_frame_time_epoch'])
                msg='index= '+str(index)+':ts= '+str(ts)+'file_df.shape= '+str(file_df.shape[0])
                myLogger.error(msg)
                line_df=json_normalize(line_data)
                file_df=file_df.append(line_df)
        
            
        conn_df_db=conn_df_db.append(conn_df,ignore_index=True)
        
        

conn_df_db=conn_df_db.fillna(0)
df_dict=conn_df_db.to_dict(orient='records')
df_dict2=[mongo_json(ln) for ln in df_dict]
    
inside_train_coll=get_db()[inside_outside_flag+'_'+train_test_flag]
inside_train_coll.insert_many(df_dict2)


#doc_list= inside_train_coll.find()
#conn_df_db=pd.DataFrame(list(doc_list))


no_columns=['timestamp','src_ip_addr','dst_ip_addr','src_port','dst_port','ip_proto','attack']
df_mat=conn_df_db.loc[:,conn_df_db.columns.difference(no_columns)].as_matrix()

#msg='start first rpca. Line131: file= '+fl
#myLogger.error(msg)
#
#rpy2.robjects.numpy2ri.activate()
#rpca_pkg=importr("rpca")
#rpca=rpca_pkg.rpca(df_mat,**{'lambda': 0.02})
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

    
print('motek')