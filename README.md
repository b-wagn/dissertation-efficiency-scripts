# Overview

This repository contains Python scripts used in my dissertation..
These scripts have been used to compute security levels and efficiency metrics (like signature size, communication complexity, ...) of cryptographic schemes I proposed in my dissertation.

Note: the scripts (with minor modifications) are also included in the appendices of the respective papers.

## Scripts for Blind Signatures
The first three scripts in `blind_signatures/` are as in the [PI-Cut-Choo paper](https://eprint.iacr.org/2022/007.pdf). They assume that we target a specific security level for the blind signature scheme, and compute a security level needed for the underlying assumption based on the security bound.
Then, given this level, they estimate what parameter sizes would be needed (e.g., what group sizes or what modulus), and then compute the corresponding sizes of communication, keys, and signatures.

+ Script `blind_signatures/ac_klr21.py` is for the Schnorr-based and Okamoto-Schnorr-based instantiations of the [KLR Boosting Transform](https://eprint.iacr.org/2021/806.pdf).
+ Script `blind_signatures/picutchoo.py` is for the CDH-based scheme in the [PI-Cut-Choo paper](https://eprint.iacr.org/2022/007.pdf).
+ Script `blind_signatures/picutchoo_friend.py` is for the RSA-based scheme from the [PI-Cut-Choo paper](https://eprint.iacr.org/2022/007.pdf).

In addition, the script `blind_signatures/raichoo.py` is as in the [Rai-Choo paper](https://eprint.iacr.org/2022/1350.pdf). It computes sizes of keys, (batched) communication, and signatures for different parameter sets of the Rai-Choo blind signature scheme, assuming it is instantiated with SHA-256 and BLS12-381.

## Scripts for Multi-Signatures
Script `multi_signatures/ms.py` is as in the [Toothpicks paper](https://eprint.iacr.org/2023/198.pdf).
For relevant two-round multi-signature schemes in the pairing-free discrete logarithm setting, this script computes sizes of keys, signatures, and communication assuming curve secp256k1. It also computes the security level guaranteed by the ROM-proof if we assume 128-bit security for the underlying assumption.

## Scripts for Threshold Signatures
Script `threshold_signatures/ts.py` is as in the the [Twinkle paper](https://eprint.iacr.org/2023/1482.pdf). For relevant threshold signature schemes in the pairing-free discrete logarithm setting, this script computes sizes of keys, signatures, and communication assuming curve secp256k1.