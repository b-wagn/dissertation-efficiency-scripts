#!/usr/bin/env python

import math
from tabulate import tabulate

#######################################################
# Functions to determine the RSA modulus length for a #
# given hardness, Formulas are taken from             #
# eprint.iacr.org/2019/260, Section 8.1              #
#######################################################
def heuristic_nfs_complexity(n, c, a):
	exponent = a*(math.log(n)**c)*((math.log(math.log(n)))**(1.0-c))
	return math.exp(exponent)

def tau(kappa):
	t = 1
	while 2**kappa > heuristic_nfs_complexity(2**(2*kappa*t), 1.0/3.0, (64/9.0)**(1.0/3.0)):
		t = t+1
	return t

def security_level_to_RSA_modulus_length(level):
	return 2*level*tau(level)





###########################################################
# Functions to compute the bit sizes of signatures,       #
# keys and communication for given modulus, scalar space, #
#  commitment modulus and statistical security parameters #
###########################################################

def size_pk(main_modulus_length, commitment_modulus_length, plambda_length):
	#size of parameters: main_modulus, 
	#invertible element modulo main_modulus, plambda
	par_size = main_modulus_length + main_modulus_length + plambda_length

	#size of pk': range element, where range is Z_N^x 
	#and N is the main_modulus
	pk_prime_size = main_modulus_length

	#size of commitment key: commitment_modulus, 
	#element modulo commitment modulus, prime e
	# we assume e = 2^16+1
	ck_size = commitment_modulus_length + commitment_modulus_length + 17 

	return par_size + pk_prime_size + ck_size

def size_sig(main_modulus_length, commitment_modulus_length, plambda_length):
	#signature consists of scalar, domain element and commitment randomness
	return plambda_length + (plambda_length + main_modulus_length) + commitment_modulus_length

#this returns coefficient of log(N) in the part of 
#the communication that grows with log(N).
def size_communication_growing(main_modulus_length, commitment_modulus_length, plambda_length, secpar, secpar_prf):
	return 2 + secpar_prf

#this returns the part of 
#the communication that does not grow with log(N).
def size_communication_constant(main_modulus_length, commitment_modulus_length, plambda_length, secpar, secpar_prf):
	return 4*secpar + plambda_length + main_modulus_length + commitment_modulus_length



##################################################
# Main part of the script, computes level of RSA #
# needed to satisfy a given security level for   #
# the scheme for a given number of signatures    #
##################################################


# Notation:
# epsilon : Success probability of adversary
# t : running time of adversary
# p : number of initiated interactions with signer oracle
# q_hash, q_hash_r, ... : number of queries for the respective hash function
# plambda_length : minumum bitlength of the prime lambda 
#                  defining the scalar space of the underlying linear function
# level_main_rsa : security level of the main RSA instance
# level_commitment_rsa: security level of the RSA instance used for the commitment scheme



# Compute the right-hand side of the inequality upper bounding the success probability 
# for an adversary against the omuf security of the scheme
def success_probability_upper_bound_omuf(log_epsilon, log_t, secpar, log_p, log_q_hash, log_q_hash_r, log_q_hash_c, log_q_hash_prime, log_q_hash_prime_prime ,plambda_length, level_main_rsa, level_commitment_rsa):

	p = 2**log_p
	q_hash = 2**log_q_hash
	q_hash_r = 2**log_q_hash_r
	q_hash_c = 2**log_q_hash_c
	q_hash_prime = 2**log_q_hash_prime

	#statistical terms in the reductions from BS to CCBS and from CCBS to EBS
	stat_term_1 = 2**(4*log_p-secpar) + 2**(3*log_p-secpar) + 2**(4*log_p-secpar) + 2**(3*log_p-secpar)
	stat_term_2 = 2**(2*log_q_hash_r-secpar) + 2**(2*log_q_hash_c-secpar) + 2**(log_p+log_q_hash_r-secpar) + 2**(log_p+log_q_hash_c-secpar) + 2**(log_p+log_q_hash_prime-secpar) + 2**(log_p+log_q_hash_prime_prime-secpar)

	#ell_BS: upper bound on the number of finished signature interactions of the linear BS scheme
	ell_BS = 3*math.log(p+1) + math.log(2) - math.log(2**log_epsilon-stat_term_2)
	log_ell_BS = math.log(ell_BS,2)

	log_term_a = 1+(2*log_q_hash+3*log_ell_BS+1+log_t-level_main_rsa)/3.0
	log_term_b = 1+(1+ell_BS)*(log_p+log_q_hash)-plambda_length
	log_term_c = 1+log_t-level_commitment_rsa
	log_term_d = 1+log_p+log_t-level_main_rsa

	total = 2**log_term_a + 2**log_term_b + 2**log_term_c + 2**log_term_d + 2*stat_term_1 + stat_term_2 
	return total


# Compute an RSA level large enough such that 
# epsilon <= success_probabilty_upper_bound_omuf ... leads to contradiction.
def rsa_level_from_epsilon_t_combination(level, log_epsilon, secpar, log_p, plambda_length):
	log_t = level + log_epsilon
	epsilon = 2**log_epsilon

	rhs = epsilon
	level_main_rsa = level 
	level_commitment_rsa = level+10
	while rhs >= epsilon:
		level_main_rsa = level_main_rsa + 1
		#for simplicity, we set all hash query parameters to be the running time
		rhs = success_probability_upper_bound_omuf(log_epsilon, log_t, secpar, log_p, log_t, log_t, log_t, log_t, log_t, plambda_length, level_main_rsa, level_commitment_rsa)

	return level_main_rsa



# Compute an RSA level large enough s.t. level bits of security are provided for omuf
def rsa_level_from_security_level(level, secpar, log_p, plambda_length):
	level_main_rsa = level

	# we consider every possible combination of epsilon and t and use the highest rsa level.
	for minus_log_epsilon in range(level+1):
		log_epsilon = -minus_log_epsilon
		l = rsa_level_from_epsilon_t_combination(level, log_epsilon, secpar, log_p, plambda_length)
		if l > level_main_rsa:
			level_main_rsa = l

	return level_main_rsa


# Compute a secpar for prf large enough such that the blindness security bound leads to a contradiction.
def secpar_prf_from_epsilon_t_combination(level,log_epsilon,main_modulus_length,commitment_modulus_length,log_N_LR,secpar):
	log_t = level + log_epsilon
	epsilon = 2**log_epsilon

	rhs = epsilon
	secpar_prf = level
	while rhs >= epsilon:
		secpar_prf = secpar_prf + 1
		#for simplicity, we set all hash query parameters to be the running time
		rhs_term_1 = (2*log_N_LR-1)* 2**(log_t-secpar_prf+2)
		rhs_term_2 = 2**(2*log_t-secpar+1)
		rhs_term_3 = 2**(log_t-secpar+2)
		rhs_term_4 = 2**(log_t-secpar_prf+2)
		rhs_term_5 = 2**(log_t-secpar_prf+2)
		rhs_term_6 = 2**(log_t-secpar+2)
		rhs = rhs_term_1 + rhs_term_2 + rhs_term_3 + rhs_term_4 + rhs_term_5 + rhs_term_6

	return secpar_prf

# Compute a secpar for prf large enough s.t. level bits of security are provided for blindness
def secpar_prf_from_security_level(level,main_modulus_length,commitment_modulus_length,log_N_LR,secpar):

	secpar_prf = level

	# we consider every possible combination of epsilon and t and use the highest secpar_prf.
	for minus_log_epsilon in range(level+1):
		log_epsilon = -minus_log_epsilon
		l = secpar_prf_from_epsilon_t_combination(level,log_epsilon,main_modulus_length,commitment_modulus_length,log_N_LR,secpar)
		if l > secpar_prf:
			secpar_prf = l

	return secpar_prf





# returns one row of the final table
def table_row(level,log_p,plambda_length):
	secpar = 3*level
	# compute the level of RSA we need for omuf
	level_main_rsa = rsa_level_from_security_level(level,secpar,log_p,plambda_length)
	level_commitment_rsa = level+10

	# compute the modulus lengths for this level
	main_modulus_length = security_level_to_RSA_modulus_length(level_main_rsa)
	commitment_modulus_length = security_level_to_RSA_modulus_length(level_commitment_rsa)

	# compute the PRF security parameter we need for blindness
	# for simplicity, we upper bound N^L and N^R by the number of interactions p
	secpar_prf = secpar_prf_from_security_level(level,main_modulus_length, commitment_modulus_length,log_p,secpar)
	
	# compute key sizes, signature sizes and communication complexity
	pk = size_pk(main_modulus_length, commitment_modulus_length, plambda_length)
	sigma = size_sig(main_modulus_length, commitment_modulus_length, plambda_length)
	comm_grow = size_communication_growing(main_modulus_length, commitment_modulus_length, plambda_length, secpar, secpar_prf)
	comm_const = size_communication_constant(main_modulus_length, commitment_modulus_length, plambda_length, secpar, secpar_prf)

	# add this set of parameters to the table
	row = [level,log_p,secpar,secpar_prf,plambda_length,level_main_rsa,level_commitment_rsa,pk/8000.0,sigma/8000.0,comm_grow/8000.0,comm_const/8000.0]
	return row





#tabulate preparation
data = [["Level", "log p", "n", "n_PRF", "|lambda|", "Level RSA (main)", "Level RSA (com)", "|pk|", "|sigma|", "Comm. a", "Comm. b"]]




#HERE you can insert the combinations you want to try.
levels = [80,128]
log_ps_class_a = [9]
plambda_lengths_class_a = [5000]
log_ps_class_b = [20]
plambda_lengths_class_b = [8000]
log_ps_class_c = [30]
plambda_lengths_class_c = [11000]



for level in levels:
	for log_p in log_ps_class_a:
		for plambda_length in plambda_lengths_class_a:
			row = table_row(level,log_p,plambda_length)
			data.append(row)

	for log_p in log_ps_class_b:
		for plambda_length in plambda_lengths_class_b:
			row = table_row(level,log_p,plambda_length)
			data.append(row)

	for log_p in log_ps_class_c:
		for plambda_length in plambda_lengths_class_c:
			row = table_row(level,log_p,plambda_length)
			data.append(row)


print(tabulate(data,headers='firstrow',tablefmt='fancy_grid'))


