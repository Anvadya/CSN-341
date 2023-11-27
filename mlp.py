import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
# %matplotlib inline
import pickle
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import accuracy_score,confusion_matrix
from sklearn.model_selection import train_test_split
import dpkt
import pandas as pd
from socket import inet_aton
import re
import os
import ipaddress 
from sklearn.neural_network import MLPClassifier
from sklearn.model_selection import train_test_split

if not os.path.exists('model.pkl'):
    rawdata = pd.read_csv("training.csv")

    def converttonumber(ipstr):
        return int(ipaddress.ip_address(ipstr))

    rawdata['cSource IP'] = rawdata['Source IP'].apply(converttonumber)
    rawdata['cDestination IP'] = rawdata['Destination IP'].apply(converttonumber)
    rawdata = rawdata.fillna(0)

    def convertprotocols(str):
        if str == 'UDP':
            return 1
        if str == 'TCP':
            return 2
        if str == 'ICMP':
            return 3
        
    def convertflagstostring(strn):
        res="1"
        # Urg:False, Ack:True, Psh:True, Rst:False, Syn:False, Fin:False
        Flgs = ["Urg:","Ack:","Psh:","Rst:","Syn:","Fin:"]
        if not isinstance(strn, str): 
            return 222222
        for i in range(6):
            match = re.search(Flgs[i], strn)
            if match:
                k = match.end()
                if strn[k] == 'T':
                    res+="1"
                else:
                    res+="0"
            else:
                res+="0"
        return eval(res)
        # if str[5] == 'T':
        #     res[0]=1
        # if str[16] == 'T':
        #     res[0]=1
        # if str[5] == 'T':
        #     res[0]=1
        # if str[5] == 'T':
        #     res[0]=1
        # if str[5] == 'T':
        #     res[0]=1
        # if str[5] == 'T':
        #     res[0]=1
    # ress = convertflagstostring('Urg:False, Ack:True, Psh:True, Rst:False, Syn:False, Fin:False')
    # type(ress)

    rawdata['cProtocol'] = rawdata['Protocol'].apply(convertprotocols)
    # print(type(rawdata['Flags'][0]))
    # print(rawdata['Flags'][0])
    rawdata['cFlags'] = rawdata['Flags'].apply(convertflagstostring)
    rawdata = rawdata.fillna(0)

    x = rawdata.drop(columns = ["Attack",'Source IP','Destination IP','Protocol','Data','DNS Query ID','Timestamp','Flags']).copy()
    x.head()
    # x.cProtocol

    def BenignMal(str):
        if str == "Benign": 
            return 0
        else:
            return 1
        
    # y = rawdata.Attack.copy()
    rawdata['cAttack'] = rawdata['Attack'].apply(BenignMal)
    y = rawdata.cAttack.copy()

    model = MLPClassifier(activation = 'relu',hidden_layer_sizes=(10,5,10), max_iter=100)

    #X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.2, shuffle =False)
    X_train, X_test, y_train, y_test = train_test_split(x, y, test_size=0.2, random_state = 151122)
    model.fit(X_train, y_train)

    model.fit(X_train,y_train)

    predictedclicked = model.predict(X_train)

    a = accuracy_score(y_train,predictedclicked)
    # print('%.2f' % a) 

    predictedtest = model.predict(X_test)
    accuracy_score(y_test,predictedtest)
    model2 = MLPClassifier(activation = 'tanh',hidden_layer_sizes=(10,5,10), max_iter=300)
    model2.fit(X_train, y_train)
    predictedtest = model2.predict(X_test)
    accuracy_score(y_test,predictedtest)

with open('model.pkl', 'wb') as model_file:
    pickle.dump(model, model_file)

# Read the model from the pickle file
with open('model.pkl', 'rb') as model_file:
    loaded_model = pickle.load(model_file)

testdata = pd.read_csv("testing.csv")

testdata['cSource IP'] = testdata['Source IP'].apply(converttonumber)
testdata['cDestination IP'] = testdata['Destination IP'].apply(converttonumber)
testdata = testdata.fillna(0)
testdata['cProtocol'] = testdata['Protocol'].apply(convertprotocols)
# print(type(testdata['Flags'][0]))
# print(testdata['Flags'][0])
testdata['cFlags'] = testdata['Flags'].apply(convertflagstostring)
testdata = testdata.fillna(0)
X_test1 = testdata.drop(columns = ["Attack",'Source IP','Destination IP','Protocol','Data','DNS Query ID','Timestamp','Flags']).copy()
X_test1.head()
predictedtest = model.predict(X_test1)
y_test = testdata.Attack
accuracy_score(y_test,predictedtest)


def dataframe_to_pcap(df, pcap_filename):
    # Create a new PCAP file
    with open(pcap_filename, 'wb') as pcap_file:
        pcap_writer = dpkt.pcap.Writer(pcap_file)

        # Iterate through rows in the DataFrame
        for index, row in df.iterrows():
            if y_test[index] == 1:
                continue
            # Extract relevant information from DataFrame columns
            timestamp = float(row['Timestamp'])
            src_ip = inet_aton(row['Source IP'])
            dst_ip = inet_aton(row['Destination IP'])
            src_port = int(row['Source Port'])
            dst_port = int(row['Destination Port'])
            protocol = row['Protocol'].lower()
            ttl = int(row['TTL'])
            icmp_type = int(row['ICMP Type'])
            flags = row['Flags']
            dns_query_id = int(row['DNS Query ID'])
            data = bytes.fromhex(row['Data'])
            data_length = int(row['Data Length'])

            # Create an Ethernet frame
            eth = dpkt.ethernet.Ethernet()

            # Create an IP packet
            ip = dpkt.ip.IP(src=src_ip, dst=dst_ip, ttl=ttl)

            # Add ICMP header if the protocol is ICMP
            if protocol == 'icmp':
                icmp = dpkt.icmp.ICMP(type=icmp_type)
                icmp.data = data
                ip.p = dpkt.ip.IP_PROTO_ICMP
                ip.data = icmp
            # Add TCP header if the protocol is TCP
            elif protocol == 'tcp':
                tcp = dpkt.tcp.TCP(sport=src_port, dport=dst_port)
                tcp.data = data
                ip.p = dpkt.ip.IP_PROTO_TCP
                ip.data = tcp
            # Add UDP header if the protocol is UDP
            elif protocol == 'udp':
                udp = dpkt.udp.UDP(sport=src_port, dport=dst_port)
                udp.data = data
                ip.p = dpkt.ip.IP_PROTO_UDP
                ip.data = udp
            else:
                raise ValueError(f"Unsupported protocol: {protocol}")

            # Add the IP packet to the Ethernet frame
            eth.data = ip

            # Write the Ethernet frame to the PCAP file
            pcap_writer.writepkt(eth.pack(), timestamp)

df = testdata

# Convert the DataFrame to PCAP
dataframe_to_pcap(df, 'benign.pcap')

