import scipy.fftpack as fft
import scipy.signal as sig
import matplotlib.pyplot as plt
import numpy as np
import pandas as pd
import math
import json
import pymongo
import random
import sys
import os
import rpy2

#import csv
#import io
#import re
import itertools
import getopt
import logging
import time
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

collection_ssl= get_db()[pcap_dir+'_ssl']

doc_tt=collection_pcap.find({'service':'ssl'})
df =  pd.DataFrame(list(doc_tt)) 

# # find first timestamp
first_ts=df['ts'].min()
# # find last timestamp
last_ts=df['ts'].max()
first_ts_rnd=first_ts.round()
last_ts_rnd=last_ts.round()
t_arr=np.arange(first_ts_rnd,last_ts_rnd)



df2=df.copy()

df2.ts=df2.ts.round()
gb2=df2.groupby(['id_orig_h','id_resp_h'])
ls=[len(kk) for kk in gb2.groups.values() ]

sum_t=pd.DataFrame()


for ss in gb2.groups.keys():
    pkt_ar=np.repeat(0,len(t_arr))
    dt=dict(zip(t_arr,pkt_ar))
    
    gtemp=gb2.get_group(ss)
    gb3=gtemp.groupby(['ts']).sum()
#    for tt in gb3.index.values:
#        dt[tt]=gb3.loc[tt]['orig_pkts']

    
    y=gb3['orig_pkts'].copy()
    t=pd.Series(gb3.index.values)
    t2=t-t.min()
    
    # #  empirically determine sampling frquency for selected pair
    dt2=t.max()-t.min()
    if dt2>0:
        sample_freq=gb3.shape[0]/dt2
    else:
        sample_freq=0  
    
    yd=y.describe()
    td=t.diff().describe()
    y1=y-y.mean()

    dft=fft.rfft(y1.values)
    freqs=fft.rfftfreq(len(y1))
    w=sig.hamming(len(y1))
    dft_sig=fft.rfft(w*(y1.values))
    
    dft2=np.abs(dft)
    if not len(dft)>1:
        dft_max=0
        freq_max=0
    else:
        dft_max=np.where(dft2==dft2[1:].max())[0][0]
        freq_max=freqs[dft_max]
    
    dft_sig2=np.abs(dft_sig)
    if not len(dft_sig)>1:
        dft_sig=0
        freq_sig_max=0
    else:
        dft_sig_max=np.where(dft_sig2==dft_sig2[1:].max())[0][0]
        freq_sig_max=freqs[dft_sig_max]
    
    lsum=[ss[0],ss[1],len(gtemp),gb3.shape[0],freq_max,freq_sig_max]
    ssum=pd.Series(lsum)
    dfsum=pd.DataFrame(ssum).T
    dfsum.columns=['orig','resp','ssl_sessions','ssl_seconds','freq_max','freq_wind_max']
    sum_t=sum_t.append(dfsum)
    sum_t.columns=['orig','resp','ssl_sessions','ssl_seconds','freq_max','freq_wind_max']
#t=np.arange(0,100,1)
#x1=np.sin(2*np.pi*t)
#x2=np.random.randn(100)
#x2[t%3==0]+=9
#x3=x2
#i=0
#while i<3:
#    x3[random.randint(0,100)]+=17
#    i+=1
#
#
#for xx in (x2,x3):
#    xx=xx-xx.mean()
#    dft=fft.rfft(xx)
#    freqs=fft.rfftfreq(len(xx),d=1/sample_freq) 
    
    fig, (ax,ax2,ax3) = plt.subplots(3,1,figsize=(14,10))

    ax.plot(t2, y)
    ax.set_xlabel('Time [s]')
    ax.set_ylabel('Signal amplitude')
    
    ax2.stem(freqs, dft2)
    ax2.set_xlabel('Frequency in Hertz [Hz]')
    ax2.set_ylabel('Frequency Domain (Spectrum) Magnitude')
    ax2.set_xlim(0, freqs.max())
    ax2.set_ylim(-5, max(dft2))
    ax3.stem(freqs, dft_sig2)
    ax3.set_xlabel('Frequency in Hertz [Hz]')
    ax3.set_ylabel('windowed Frequency Domain (Spectrum) Magnitude')
    ax3.set_xlim(0, freqs.max())
    ax3.set_ylim(-5, max(dft_sig2))
    
    plt.show()
    fig.savefig(str(ss)+'2.png')
    sum_t.to_csv('dft_summary.csv')

#f = 10  # Frequency, in cycles per second, or Hertz
#f_s = 100  # Sampling rate, or number of measurements per second
#
#t = np.linspace(0, 2, 2 * f_s, endpoint=False)
#x2 = np.sin(f * 2 * np.pi * t)
#
#fig, ax = plt.subplots()
#ax.plot(t, x2)
#ax.set_xlabel('Time [s]')
#ax.set_ylabel('Signal amplitude')
#
#from scipy import fftpack
#
#X2 = fftpack.fft(x2)
#freqs = fftpack.fftfreq(len(x2)) * f_s
#
#fig, ax = plt.subplots()
#
#ax.stem(freqs, np.abs(X2))
#ax.set_xlabel('Frequency in Hertz [Hz]')
#ax.set_ylabel('Frequency Domain (Spectrum) Magnitude')
#ax.set_xlim(-f_s / 2, f_s / 2)
#ax.set_ylim(-5, 110)

 # Number of sample points
#N = 600
# # sample spacing
#T = 1.0 / 800.0
#
#x = np.linspace(0.0, N*T, N)
#y = np.sin(50.0 * 2.0*np.pi*x) + 0.5*np.sin(80.0 * 2.0*np.pi*x)
#yf = fft(y)
#xf = np.linspace(0.0, 1.0/(2.0*T), N//2)
#
#plt.plot(xf, 2.0/N * np.abs(yf[0:N//2]))
#plt.grid()
#plt.show()
