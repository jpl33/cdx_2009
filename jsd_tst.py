# -*- coding: utf-8 -*-
"""
Created on Sun Apr 15 14:51:02 2018

@author: root
"""

import numpy as np
import pandas as pd
import matplotlib as plt

def jsd(df,mcd):
    dff=pd.concat([df,mcd],axis=1)
    dff.columns=['df','mcd']    
    dff['m']=dff.sum(axis=1)/2
    dff['kl_df']=dff.df*np.log(dff.df/dff.m)
    dff['kl_mcd']=dff.mcd*np.log(dff.mcd/dff.m)
    dff['jsd']=dff.loc[:,'kl_df':'kl_mcd'].sum(axis=1)/2
    dff.fillna(0,inplace=True)
    return dff.jsd



a=np.array(range(0,100))
b=np.random.choice(a,20,replace=False)
ll=[int(i) for i in set(a)-set(b)]
c=np.random.choice(ll,15,replace=False)
d=np.random.choice([int(i) for i in set(a)-set(b)-set(c)],10,replace=False)
e=np.random.choice([int(i) for i in set(a)-set(b)-set(c)-set(d)],5,replace=False)

ser=pd.Series(list(np.repeat('a',100)))
ser.iloc[b]='b'
ser.iloc[c]='c'
ser.iloc[d]='d'
ser.iloc[e]='e'
df_jsd=pd.DataFrame(ser,columns=['state'])
ser_vc=ser.value_counts()/ser.shape[0]
df_jsd['state_freq']=0.5
for cc in ser_vc.index.values:
    df_jsd.loc[ df_jsd.state==cc,'state_freq']=ser_vc.loc[cc]
df_jsd['state_freq_n']=(df_jsd.state_freq-df_jsd.state_freq.mean() )/df_jsd.state_freq.std(ddof=0)

t_plt=np.random.standard_normal(size=50)
t_plt=np.append(t_plt,np.random.standard_t(df=24,size=50))
t_plt=t_plt.round(2)
nrm_plt=np.random.standard_normal(size=100)
nrm_plt=nrm_plt.round(2)

mc1=np.random.choice(df_jsd.loc[df_jsd.state=='a'].index.values,size=47,replace=False)
mc2=np.random.choice(df_jsd.loc[df_jsd.state=='b'].index.values,size=12,replace=False)
mc3=np.random.choice(df_jsd.loc[df_jsd.state=='c'].index.values,size=9,replace=False)
mc4=np.random.choice(df_jsd.loc[df_jsd.state=='d'].index.values,size=5,replace=False)


mcdf=np.append(mc1,np.append(mc2,np.append(mc3,mc4)))

df_jsd['mcd']=False
df_jsd.iloc[mcdf,df_jsd.columns.get_loc('mcd')]=True

df_jsd['mcd_freq']=0
mcd_fr=df_jsd.loc[df_jsd.mcd==True,'state'].value_counts()/75
for cc in mcd_fr.index.values:
    df_jsd.loc[df_jsd.state==cc,'mcd_freq']=mcd_fr.loc[cc]

df_jsd['jsd']=jsd(df_jsd.state_freq,df_jsd.mcd_freq)
df_jsd['jsd_n_std']=(df_jsd.jsd-df_jsd.jsd.mean())/df_jsd.jsd.std(ddof=0)
df_jsd['jsd_n_mm']=(df_jsd.jsd-df_jsd.jsd.min())/(df_jsd.jsd.max()-df_jsd.jsd.min())

fig, axs = plt.pyplot.subplots(1,4, sharey=True, tight_layout=True)

axs[0].hist(df_jsd.state_freq)
axs[1].hist(df_jsd.mcd_freq)
axs[2].hist(df_jsd.jsd)
axs[3].hist(df_jsd.jsd_n_mm)

#df_jsd['mcd']pd.Series(mcdf).value_counts()/75