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

def size_pk(group_size_length):
	#group generator,  public key (group element)
	return 2*group_size_length

def size_sig_schnorr(group_size_length, commitment_randomness_length):
	#signature contains c',s', and a commitment randomness
	return 2*group_size_length + commitment_randomness_length

def size_sig_okamoto_schnorr(group_size_length, commitment_randomness_length):
	#signature contains c',s_1',s_2', and a commitment randomness
	return 3*group_size_length + commitment_randomness_length


########################################################################
# Main part of the script, computes level of security for DLOG needed  #
# to satisfy a given security level for the scheme for a given number  #
# of signatures                                                        #
########################################################################


# Notation:
# epsilon : Success probability of adversary
# t : running time of adversary
# q : number of initiated interactions with signer oracle
# level_dlog : security level of the underlying DLOG instance

# Compute the right-hand side of the inequality upper bounding the success probability 
# for an adversary against the omuf security of the scheme
def success_probability_upper_bound_omuf(log_epsilon, log_t, log_q, level_dlog):
	q = 2**log_q

	#ell_BS: upper bound on the number of finished signature interactions of the linear BS scheme
	ell_BS = 3*math.log(q+1) + math.log(2) - math.log(2**log_epsilon)

	term1 = ell_BS * 2**(2+(1+log_t-level_dlog+2*log_t)/3.0)
	term2 = 2**(log_q + 1 + log_t - level_dlog)
	term3 = 2**(log_q*(ell_BS+1) -level_dlog)

	return term1 + term2 + term3



# Compute a DLOG level large enough such that 
# epsilon <= success_probabilty_upper_bound_omuf ... leads to contradiction.
def dlog_level_from_epsilon_t_combination(level, log_epsilon, log_q):
	log_t = level + log_epsilon
	epsilon = 2**log_epsilon

	rhs = epsilon
	# if we started from level, we would result in overflows as the RHS is too large.
	level_dlog = 47*level 
	while rhs >= epsilon:
		level_dlog = level_dlog + 1
		rhs = success_probability_upper_bound_omuf(log_epsilon, log_t, log_q, level_dlog)

	return level_dlog



# Compute a DLOG level large enough s.t. level bits of security are provided for omuf
def dlog_level_from_security_level(level, log_q):
	level_dlog = level

	# we consider every possible combination of epsilon and t and use the highest rsa level.
	for minus_log_epsilon in range(level+1):
		log_epsilon = -minus_log_epsilon
		l = dlog_level_from_epsilon_t_combination(level, log_epsilon, log_q)
		if l > level_dlog:
			level_dlog = l

	return level_dlog





level = 128
log_q = 30

commitment_randomness_length = 128
level_dlog = dlog_level_from_security_level(level,log_q)
group_size_length = security_level_to_group_size_length(level_dlog)
size_pk = size_pk(group_size_length)
size_sig_schnorr = size_sig_schnorr(group_size_length, commitment_randomness_length)
size_sig_okamoto_schnorr = size_sig_okamoto_schnorr(group_size_length, commitment_randomness_length)

print("Want to support q = 2^" + str(log_q) + " signatures.")
print("==> Need level for DLOG >= " + str(level_dlog))
print("==> Need group bit size for DLOG >= " + str(group_size_length))
print("==> Public Key Size (in KB) >= " + str(size_pk/8000.0))
print("==> Schnorr Signature Size (in KB) >= " + str(size_sig_schnorr/8000.0))
print("==> Okamoto-Schnorr Signature Size (in KB) >= " + str(size_sig_okamoto_schnorr/8000.0))




