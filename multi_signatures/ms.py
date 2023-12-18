#!/usr/bin/env python


################PURPOSE#OF#THIS#SCRIPT##################
# For each scheme, we estimate the security level      #
# that is guaranteed by the security bound.            #
# We also compute the concrete sizes of public keys,   #
# signatures, and communication complexity per signer. #
# We assume a certain number of hash and signing       #
# queries; we assume that secp256k1 is used and the    #
# underlying assumptions/problems offer a security     #
# level of 128 bit.                                    #
########################################################

import math
from tabulate import tabulate



#number of hash queries and signing queries
log_q_h = 30
log_q_s = 20

#hardness of the underlying assumption
kappa = 128

#sizes of group elements, exponents, and statistical security parameter
#we assume secp256k1 and all sizes in bits
secpar = 128
sizege = 33*8
sizefe = 256


#################Define Schemes#######################################
# Note: we estimate an upper bound on epsilon, assuming unit time    #
# One can see that this favors schemes with rewinding due to the sqrt#
######################################################################


musigtwo = {
	"name": "Musig2",
	"level": 0.25 * (kappa-2-3*log_q_h),
	"pk": sizege,
	"comm": 4*sizege+sizefe,
	"sig": sizege+sizefe,
}

hbms = {
	"name": "HBMS",
	"level": 0.25 * (kappa-2-3*log_q_h - 4*log_q_s),
	"pk": sizege,
	"comm": sizege+2*sizefe,
	"sig": sizege+2*sizefe,
}

tz = {
	"name": "TZ",
	"level": 0.25 * (kappa-3-3*log_q_h),
	"pk": sizege,
	"comm": 4*sizege+2*sizefe,
	"sig": sizege+2*sizefe,
}

tssho = {
	"name": "TSSHO",
	"level": kappa - 2 - log_q_s,
	"pk": 2*sizege,
	"comm": 2*sizege+2*sizefe,
	"sig": 3*sizefe,
}

chopsticksone = {
	"name": "Chopsticks 1",
	"level": kappa - 2 - log_q_s,
	"pk": 2*sizege,
	"comm": 3*sizege+1*sizefe+secpar,
	"sig": 4*sizefe+2*secpar,
}

chopstickstwo = {
	"name": "Chopsticks 2",
	"level": kappa - 2,
	"pk": 4*sizege,
	"comm": 6*sizege+2*sizefe+secpar+1,
	"sig": 8*sizefe+4*secpar+secpar, #assuming number of signers <= secpar
}

toothone = {
	"name": "Toothpicks 1",
	"level": kappa - 2 - log_q_s,
	"pk": 2*sizege,
	"comm": 2*sizege+1*sizefe+secpar,
	"sig": 3*sizefe+2*secpar,
}

toothtwo = {
	"name": "Toothpicks 2",
	"level": kappa - 3,
	"pk": 4*sizege,
	"comm": 2*sizege+1*sizefe+secpar+1,
	"sig": 3*sizefe+2*secpar+secpar, #assuming number of signers <= secpar
}

schemes = [musigtwo,hbms,tz,tssho,chopsticksone,chopstickstwo,toothone,toothtwo]



#####################Main Part########################

def bytes(x):
	return int(round(x/8.0,0))

data = [["Scheme", "Security Level", "Pk", "Communicaton", "Signature"]]

for s in schemes:
	data.append([s["name"],int(s["level"]),bytes(s["pk"]),bytes(s["comm"]),bytes(s["sig"])])


print(tabulate(data,headers='firstrow',tablefmt='fancy_grid'))
