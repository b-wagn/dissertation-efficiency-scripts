#!/usr/bin/env python


################PURPOSE#OF#THIS#SCRIPT##################
# For each scheme, we compute sizes of public keys,    #
# signatures, and communication complexity per signer. #
# we assume that secp256k1 is used                     #
########################################################

import math
from tabulate import tabulate

#sizes of group elements and exponents
#we assume secp256k1; all sizes in bytes
sizec = 16 # size of a challenge
sizege = 33
sizefe = 32
sizehash = 32

sizeschnorrsig = sizec+sizefe

frost = {
	"name": "Frost",
	"pk": sizege,
	"comm": 2*sizege + sizefe,
	"sig": sizeschnorrsig,
}

tz = {
    "name": "TZ",
	"pk": sizege,
	"comm": 2*sizege + 2*sizefe,
	"sig": sizege + 2*sizefe,
}

sparkle = {
    "name": "Sparkle",
	"pk": sizege,
	"comm": sizehash + sizege + sizefe,
	"sig": sizeschnorrsig,
}

sizerange = 2*sizege
sizedomain = 2*sizefe
twinkle = {
    "name": "Twinkle-DDH",
	"pk": sizerange,
	"comm": sizehash + 3*sizerange + sizedomain,
	"sig": sizerange + sizedomain + sizec,
}

sizerange = sizege
sizedomain = sizefe
twinkleOneMore = {
    "name": "Twinkle-OMCDH",
	"pk": sizerange,
	"comm": sizehash + 3*sizerange + sizedomain,
	"sig": sizerange + sizedomain + sizec,
}

schemes = [frost,tz,sparkle,twinkle,twinkleOneMore]

#####################Main Part########################

data = [["Scheme", "PK", "Communication (per Signer)", "Signature Size"]]

for s in schemes:
	data.append([s["name"], s["pk"], s["comm"], s["sig"]])

print(tabulate(data,headers='firstrow',tablefmt='fancy_grid'))
