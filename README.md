# CSN-341

This is the group project for the course CSN-341 (Computer Networks), on the topic "Developing an Efficient Deep Learning-Based Network Traffic Classifier for Enhanced Network Security and Performance." 

## Team Members:
1. Anvadya Khare (21114015)
2. Tejas Sajwan (21114106)
3. Amandeep Singh (21411005)
4. Mehak Sharma (21114060)
5. Manashree Kalode (21114057)
6. Nishita Singh (21114068)
7. Gujar Neha Pankaj (21114039)
8. Akhil Punia (21114008)
9. Bhoomi Bonal (21114028)
10. Prerna (21114075)

## Environment Used
A custom dataplane for forwarding and processing networking packets was used, it must be installed to use the custom dataplane (though the code will run using the standard Linux implementation of TCP also) in the dataplane folder (we have used IX Operating System with userspace dataplane developed at Stanford and EPFL). 

The dataplane requires the use of specific Intel NIC (refer to IX System Requirements). 

## Description
The System receives pcap (packet capture)  files as input from the network under observation. These are screened by a set of preliminary policies defined by a Decision Tree Classifier, to classify the packets into Malicious and Non-Malicious. The packets are further passed onto the DL Model to be classified with certainty.

## How to use?

1. Fork repository from https://github.com/Anvadya/CSN-341/tree/main
2. Run the bash script file run.sh , The script contains the main function, which calls other functions to perform packet pre-processing, decision-tree based screening(firewall), and DL-model based classification(Flow Transformer).
3. The resultant accuracy of the DL-model is obtained.
