#!/usr/bin/env python

import math
from tabulate import tabulate

################PURPOSE#OF#THIS#SCRIPT####################
# Compute sizes of communication, signatures, keys for   #
# the Rai-Choo blind signature scheme, instantiated with #
# standard components (namely, SHA-256 and BLS12-381 )   #
##########################################################


#Fixed paramters, e.g., group element size
size_group_one_element = 48*8 #use BLS12-381
size_group_two_element = 96*8 #use BLS12-381
secpar = 256 #use SHA-256
level = 128
log_q = 30




############################################
# Functions to determine the bit sizes of  #
# signatures, keys, and communication for  #
# given parameters                         #
############################################

def size_pk(K, N):
	return size_group_one_element+size_group_two_element

def size_sig(K, N):
	size_comm_rand = K*secpar
	size_pks = (K-1)*(size_group_one_element+size_group_two_element)
	size_aggregate_sig = size_group_one_element
	return size_comm_rand+size_pks+size_aggregate_sig

def size_communication_batched(K, N, L):
	size_cc_index = K*math.ceil(math.log(N,2))
	size_opening = K*((N-1)*(secpar+ L*secpar)+L*size_group_one_element+secpar)
	size_pks = (K-1)*(size_group_one_element+size_group_two_element)
	size_response = L*size_group_one_element
	return (size_cc_index + size_opening + size_pks + size_response)/float(L)


##########################################################


# Determine a minimum value K for given security level,
# number of queries and N, such that the term in the omuf
# bound q/N^K becomes small enough
# Setting K smaller would lead to no solution at all
def min_plausible_K(N):
	return math.ceil((level+log_q) / math.log(N,2))+ 1

# Compute a row of the table, i.e. efficiency measures for given
# parameters K, N, and batch sizes
def table_row(K, N, logLs):
	pk = size_pk(K, N)
	sig = size_sig(K, N)

	row = [level,log_q,K,N,pk/8000.0,sig/8000.0]
	for logL in logLs:
		L = 2**logL
		comm = size_communication_batched(K, N, L)
		row.append(comm/8000.0)

	return row



#HERE you can insert the combinations you want to try.
logNs = [2,3,5]
logLs = [0,2,4,8]

#tabulate preparation
data = [["Level", "log_q", "K", "N", "|pk|", "|sigma|"] + ["Comm L = " + str(2**logL) for logL in logLs]]
print("")

for logN in logNs:
	N = 2**logN
	K = min_plausible_K(N)
	row = table_row(K,N,logLs)
	data.append(row)

print(tabulate(data,headers='firstrow',tablefmt='fancy_grid'))
