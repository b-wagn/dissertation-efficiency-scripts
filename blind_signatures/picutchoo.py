#!/usr/bin/env python

import math
from tabulate import tabulate


######################################################################
# Functions to determine the (log of) group size for given hardness  #
# Formulas are taken from eprint.iacr.org/2019/260, Section 8.1     #
######################################################################


def security_level_to_group_size_length(level):
	return 2*level+1

#######################################################################
# Functions to compute the bit sizes of signatures and keys and       # 
# communication complexity for given group size, repetition parameter #
# K, commitment group size and statistical security parameters        #
#######################################################################

def size_pk(K, main_group_size_length, main_group_size_length_pk, commitment_group_size_length):
	#group generator, K public keys (group elements), 2 group elements for the commitment
	return main_group_size_length + K*main_group_size_length_pk + 2* commitment_group_size_length

def size_sig(K, main_group_size_length, commitment_group_size_length):
	#signature contains one aggregated group element and K times a commitment randomness
	return main_group_size_length + K * commitment_group_size_length

#this returns coefficient of log(N) in the part of the communication that grows with log(N).
def size_communication_growing(K, main_group_size_length, commitment_group_size_length, secpar, secpar_prf):
	return (1+K*secpar_prf)
	
#this returns the part of the communication that does not grow with log(N).
def size_communication_constant(K, main_group_size_length, commitment_group_size_length, secpar, secpar_prf):
	return (K+5)*secpar + (K+1)*main_group_size_length + commitment_group_size_length + (K*math.log(K,2)+1-K)*secpar_prf



########################################################################
# Main part of the script, computes level of security for DLOG needed  #
# to satisfy a given security level for the scheme for a given number  #
# of signatures                                                        #
########################################################################


# Notation:
# epsilon : Success probability of adversary
# t : running time of adversary
# q : number of initiated interactions with signer oracle
# q_hash, q_hash_r, ... : number of queries for the respective hash function
# level_main_dlog : security level of the main DLOG/CDH instance
# level_commitment_dlog: security level of the DLOG/CDH instance used for the commitment scheme



# Compute the right-hand side of the inequality upper bounding the success probability 
# for an adversary against the omuf security of the scheme
def success_probability_upper_bound(log_t, secpar, K, log_q, log_q_hash, log_q_hash_r, log_q_hash_c, log_q_hash_prime, level_main_dlog, level_commitment_dlog):
	
	#statistical term
	stat_term_a = 2**(2*log_q_hash_r-secpar)
	stat_term_b = 2**(2*log_q_hash_c-secpar)
	stat_term_c = 2**(log_q+log_q_hash_r-secpar)
	stat_term_d = K* 2**(log_q+log_q_hash_r-secpar)
	stat_term_e = 2**(log_q+log_q_hash_c-secpar)
	stat_term_f = 2**(log_q+log_q_hash_prime-secpar+1)
	stat_term = stat_term_a + stat_term_b + stat_term_c + stat_term_d + stat_term_e + stat_term_f
	
	term_a = 2**(-level_commitment_dlog+log_t)
	term_b = K*2**(-(2*level_main_dlog+1))
	term_c = 4*K*2**(log_q-level_main_dlog+log_t)
	term_d = stat_term

	total = 2*(term_a+term_b+term_c+term_d)
	return total


# Compute an dlog level large enough such that 
# epsilon <= success_probability_upper_bound_ ... leads to contradiction.
def dlog_level_from_epsilon_t_combination(level, log_epsilon, secpar, log_q, K):
	log_t = level + log_epsilon
	epsilon = 2**log_epsilon

	rhs = epsilon
	level_main_dlog = level+10 
	level_commitment_dlog = level+10
	while rhs >= epsilon:
		level_main_dlog = level_main_dlog + 1
		#for simplicity, we set all hash query parameters to be the running time
		rhs =  success_probability_upper_bound(log_t, secpar, K, log_q, log_t, log_t, log_t, log_t, level_main_dlog, level_commitment_dlog)

	return level_main_dlog



# Compute an DLOG level large enough s.t. level bits of security are provided
def dlog_level_from_security_level(level, secpar, log_q, K):
	level_main_dlog = level

	# we consider every possible combination of epsilon and t and use the highest dlog level.
	for minus_log_epsilon in range(level+1):
		log_epsilon = -minus_log_epsilon
		l = dlog_level_from_epsilon_t_combination(level, log_epsilon, secpar, log_q, K)
		if l > level_main_dlog:
			level_main_dlog = l

	return level_main_dlog





# Compute a secpar for prf large enough such that the 
# blindness security bound leads to a contradiction.
def secpar_prf_from_epsilon_t_combination(level,log_epsilon,log_N_LR,K,secpar):
	log_t = level + log_epsilon
	epsilon = 2**log_epsilon

	rhs = epsilon
	secpar_prf = level
	while rhs*2**(log_t) >= epsilon:
		secpar_prf = secpar_prf + 1
		#for simplicity, we set all hash query parameters to be the running time
		rhs_term_1 = (2*log_N_LR + 2*math.log(K,2)-1)*K*2**(log_t-secpar_prf+2)
		rhs_term_2 = 2**(2*log_t-secpar+1)
		rhs_term_3 = 2**(log_t-secpar+2)
		rhs_term_4 = K* 2**(log_t-secpar_prf+2)
		rhs_term_5 = K* 2**(log_t-secpar_prf+2)
		rhs = rhs_term_1 + rhs_term_2 + rhs_term_3 + rhs_term_4 + rhs_term_5

	return secpar_prf

# Compute a secpar for prf large enough s.t. level bits of security are provided for blindness
def secpar_prf_from_security_level(level,log_N_LR,K,secpar):

	secpar_prf = level

	# we consider every possible combination of epsilon and t and use the highest secpar_prf.
	for minus_log_epsilon in range(level+1):
		log_epsilon = -minus_log_epsilon
		l = secpar_prf_from_epsilon_t_combination(level,log_epsilon,log_N_LR,K,secpar)
		if l > secpar_prf:
			secpar_prf = l

	return secpar_prf





# checks the condition that vartheta and K have to satisfy in order to apply the OMUF theorem
# for the security level we aim to achieve
def vartheta_from_constraint(level,K):
	denom = 1.0 - (math.log(2**(level+1))/float(K))
	return (1.0/denom) + 0.1


#returns the minimum integer K such that there even exists a positive vartheta
def minimum_plausible_K(level):
	return int(math.log(2**(level+1))+1)
	return int(math.log(2**(level+1))/2.0+1)

# returns one row of the final table
def table_row(level,log_q,K):
	secpar = 4*level

	# compute the vartheta we need to satisfy the constraint
	vartheta = vartheta_from_constraint(level,K)
	if vartheta <= 0:
		return [] 

	# compute the level of DLOG we need
	level_main_dlog = dlog_level_from_security_level(level,secpar,log_q,K)
	level_commitment_dlog = level+10

	# compute the group elements lengths for this level
	main_group_size_length = security_level_to_group_size_length(level_main_dlog)
	# public key is in G_2, so it is bigger
	main_group_size_length_pk = main_group_size_length*3
	commitment_group_size_length = security_level_to_group_size_length(level_commitment_dlog)

	# compute the PRF security parameter we need for blindness
	# for simplicity, we upper bound N^L and N^R by the number of interactions q
	secpar_prf = secpar_prf_from_security_level(level,log_q,K,secpar)
	
	# compute key sizes, signature sizes and communication complexity
	pk = size_pk(K, main_group_size_length, main_group_size_length_pk, commitment_group_size_length)
	sigma = size_sig(K, main_group_size_length, commitment_group_size_length)
	comm_grow = size_communication_growing(K, main_group_size_length, commitment_group_size_length, secpar, secpar_prf)
	comm_const = size_communication_constant(K, main_group_size_length, commitment_group_size_length, secpar, secpar_prf)

	# add this set of parameters to the table
	row = [level,log_q,secpar,secpar_prf,vartheta,K,level_main_dlog,level_commitment_dlog,pk/8000.0,sigma/8000.0,comm_grow/8000.0,comm_const/8000.0]
	return row






#HERE you can insert the combinations you want to try.
levels = [80,128]
log_qs = [20,30]

#tabulate preparation
data = [["Level", "log_q", "n", "n_PRF", "vartheta", "K", "Level DLOG (main)", "Level DLOG (com)", "|pk|", "|sigma|", "Comm. a", "Comm. b"]]
print("")

for level in levels:
	for log_q in log_qs:
		K_init = minimum_plausible_K(level)
		for K_off in range(0,30,10):
			K = K_init+K_off
			row = table_row(level,log_q,K)
			data.append(row)

print(tabulate(data,headers='firstrow',tablefmt='fancy_grid'))



