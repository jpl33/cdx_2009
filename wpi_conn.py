# -*- coding: utf-8 -*-
"""
Created on Tue Aug 14 12:06:19 2018

@author: root
"""

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


wpi_dir='wpi\\'

dff=pd.DataFrame()
dl=next(os.walk(home_dir+wpi_dir))[2]
dl.sort()
remove=[]
for d in dl:
    if ( not d.startswith(('inside','outside'))  ):
        remove.append(d)
prcs_file= open('processed_wpi_files.txt', 'r+')
for l in prcs_file.readlines():
    l=l.split("\n")[0]
    if len(l)>1:
        remove.append(l)
for r in remove:
    dl.remove(r)

important_ports=[80,139,445,137,135,111,23,21,22]
protocols=[ 'ICMP', 'sadmind',
'Portmap', 'TELNET', 'TCP', 'FTP', 'HTTP']

for fl in dl: 
    with open(home_dir+wpi_dir +fl,'r') as wpi_f:
        from pandas.io.json import json_normalize
        #for line in itertools.islice(wpi_f, coll_count,None):
        file_data=json.loads(wpi_f.read())
        file_df=json_normalize(file_data)
        conn_df=pd.DataFrame(index=file_df.index.values)
        src_ip_vec=file_df.loc[:,'_source.layers.ip.ip.src']
        dst_ip_vec=file_df.loc[:,'_source.layers.ip.ip.dst']
        ts_vec=file_df.loc[:,'_source.layers.frame.frame.time_epoch']
        ip_proto_vec=file_df.loc[:,'_source.layers.ip.ip.proto']
        ip_proto_dict={1:'icmp',17:'udp',6:'tcp'}
        udp_ll=[c for c in file_df.columns if 'udp' in c]
        tcp_ll=[c for c in file_df.columns if 'tcp' in c]
        if len(udp_ll)>0:
            src_port_udp_vec=file_df.loc[:,'_source.layers.udp.udp.srcport']
            dst_port_udp_vec=file_df.loc[:,'_source.layers.udp.udp.dstport']
        else:
            src_port_udp_vec=pd.Series(np.repeat(0,file_df.shape[0]))
            dst_port_udp_vec=pd.Series(np.repeat(0,file_df.shape[0]))

        if len(tcp_ll)>0:
            src_port_tcp_vec=file_df.loc[:,'_source.layers.tcp.tcp.srcport']
            dst_port_tcp_vec=file_df.loc[:,'_source.layers.tcp.tcp.dstport']
        else:
            src_port_tcp_vec=pd.Series(np.repeat(0,file_df.shape[0]))
            dst_port_tcp_vec=pd.Series(np.repeat(0,file_df.shape[0]))
        
        src_port_vec=src_port_udp_vec.combine(src_port_tcp_vec,lambda x1, x2: x2 if pd.isnull(x1) else x1)
        dst_port_vec=dst_port_udp_vec.combine(dst_port_tcp_vec,lambda x1, x2: x2 if pd.isnull(x1) else x1)
        conn_df['timestamp']=ts_vec
        conn_df['src_ip_addr']=src_ip_vec
        conn_df['dst_ip_addr']=dst_ip_vec
        conn_df['ip_proto']=pd.Series(ip_proto_vec).astype(int).apply(lambda x: ip_proto_dict[x])
        conn_df['src_port']=src_port_vec
        conn_df['dst_port']=dst_port_vec
        
        important_src_port_vec=conn_df.src_port.astype(int).apply(lambda x: 1 if x in important_ports else 0)
        important_dst_port_vec=conn_df.dst_port.astype(int).apply(lambda x: 1 if x in important_ports else 0)
        high_src_port_vec=conn_df.src_port.astype(int).apply(lambda x: 1 if x >1024 else 0)
        high_dst_port_vec=conn_df.dst_port.astype(int).apply(lambda x: 1 if x >1024 else 0)
        missing_src_port_vec=pd.DataFrame(conn_df.src_port.astype(int).apply(lambda x: 1 if x ==0 else 0).values,columns=['missing_src_port'])
        missing_dst_port_vec=pd.DataFrame(conn_df.dst_port.astype(int).apply(lambda x: 1 if x ==0 else 0).values,columns=['missing_dst_port'])
        
        df_dummies_1=pd.get_dummies(conn_df[['src_ip_addr','dst_ip_addr']])
        df_dummies_2=pd.get_dummies(important_src_port_vec,prefix='important_src_port')
        df_dummies_3=pd.get_dummies(important_dst_port_vec,prefix='important_dst_port')
        df_dummies_4=pd.get_dummies(high_src_port_vec,prefix='high_src_port')
        df_dummies_5=pd.get_dummies(high_dst_port_vec,prefix='high_dst_port')
        features=[conn_df,df_dummies_1,df_dummies_2,df_dummies_3,df_dummies_4,df_dummies_5,missing_src_port_vec,missing_dst_port_vec]
        conn_df=pd.concat(features,axis=1)
        