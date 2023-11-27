# Cerberus

This is the group project for the course CSN-341 (Computer Networks), on the topic "Developing an Efficient Deep Learning-Based Network Traffic Classifier for Enhanced Network Security and Performance."

Cerberus comprises three main parts:

- A high-performance, user-space network stack designed for efficient data processing
- An Efficient Network Packet Classifier Leveraging Decision Trees
- Network packet classification utilizing deep learning methodologies

## Environment Used

A custom dataplane for forwarding and processing networking packets was used, it must be installed to use the custom dataplane (though the code will run using the standard Linux implementation of TCP also) from the IX repository (which required `dpdk` and `Dune`) (we have used IX Operating System with userspace dataplane developed at Stanford and EPFL).

The dataplane requires the use of specific Intel NIC (refer to IX System Requirements).

## Description

The System receives pcap (packet capture) files as input from the network under observation. These are screened by a set of preliminary policies defined by a Decision Tree Classifier, to classify the packets into Malicious and Non-Malicious. The packets are further passed onto the DL Model to be classified with certainty.

## How to use?

1. Fork repository from https://github.com/Anvadya/CSN-341/
2. Run the bash script file run.sh , the script contains the main function, which calls other functions to perform 
    1. Packet pre-processing
    2. Decision-tree based screening
    3. DL-model based classification

## References

- [Issues with Private IP Addressing in the Internet](https://www.ietf.org/archive/id/draft-kirkham-private-ip-sp-cores-01.html)
- [Low-Rate DDoS Attack Detection Using Expectation of Packet Size](https://www.hindawi.com/journals/scn/2017/3691629/)
- [Computer Network: An Implementation of MAC Spoofing](https://www.researchgate.net/publication/371440124_Computer_Network_An_Implementation_of_MAC_Spoofing)
- [FlowTransformer](https://arxiv.org/pdf/2304.14746.pdf)

## Team Members:

- Anvadya Khare (21114015)
- Tejas Sajwan (21114106)
- Amandeep Singh (21411005)
- Mehak Sharma (21114060)
- Manashree Kalode (21114057)
- Nishita Singh (21114068)
- Gujar Neha Pankaj (21114039)
- Akhil Punia (21114008)
- Bhoomi Bonal (21114028)
- Prerna (21114075)
