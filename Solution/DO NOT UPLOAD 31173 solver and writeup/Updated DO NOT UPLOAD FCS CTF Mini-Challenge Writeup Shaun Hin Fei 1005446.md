# FCS CTF Mini-Challenge Writeup 
### Author: Shaun Hin Fei 1005446

## Introduction
Googling *"rsa ctf writeup"* yields many search results from ctf challenges that have poorly implemented RSA for exploitation.

A similar search for *"elgamal ctf writeup"* yields far lesser results. Based on the link [inspiration for challenge](https://ctftime.org/writeup/19075), we have an inspiration for utilising the homomorphic properties of ElGamal for a decent CTF challenge.

However, that would be plagiarism. Hence, we actually begin our research for a suitable cryptographic system on [starting point of research](https://en.wikipedia.org/wiki/ElGamal_encryption) instead.

## Selection
Browsing through the page, we see that ElGamal is unconditionally malleable as proven by access to the encryption and decryption services of the oracle in the inspiration writeup. However, schemes that are secure against this attack, namely the **Cramer-Shoup** cryptosystem is suggested if the Decisional Diffie-Hellman (DDH) assumption holds for cyclic group G.

Since the DDH assumption relies on the hardness of solving the discrete logarithm problem in well chosen groups where generators "look like" random elements in G, the Cramer-Shoup cryptosystem is ideal for testing the intuition on the discrete logarithm problem without the solutions being easily found on the internet. 

Furthermore, a quick search for *"cramer-shoup ctf write up"* yields nearly no results of relevant challenges posed on the internet.

Hence, this rather novel cryptosystem in the CTF world is selected for our challenge.

## Implementation
We have already coded up both the challenge code and the attack script to solve the challenge. 

Therefore, our **challenge code (attached)** would explain our implementation of the chosen scheme, and we have the following instructions to point the challengers in the right direction.

### Instructions/Hints
```
Last month, our overzealous rookie security engineers at Campbell Soup Security Pte. Ltd. decided to implement their own upgraded version of ElGamal in an oracle to encrypt our super secret patented Campbell Soup Security recipe (FLAG). 

They used some new-fangled system that they found through a link on the ElGamal encryption Wikipedia page as a guide to build the oracle, but looks like they put more effort into the graphics than actually following the system. Sigh.

Unsurprisingly, we have received reports that an anonymous actor is continuously trying to decrypt our super secret patented Campbell Soup Security recipe using this rookie oracle. 

Therefore, we have put the oracle under maintenance and our valued customers may only decrypt their own stocked up soup recipes for the time being. Of course, employees are still welcome to read our super secret patented Campbell Soup Security recipe.

Which brings us to today. It is with a heavy heart that we announce our imminent failure in securing our super secret patented Campbell Soup Security recipe. Despite our best efforts, we are seeing an increase of suspicious traffic in high volumes at perfectly precise intervals, and our senior security engineers tell us that the anonymous actor is minutes away from succeeding...
```

## Analysis
We have an **attack script (also attached)** required to solve the challenge making use of the poor implementation to exploit the system using **chosen ciphertext attack**.

The accompanying attack script takes **at most 10 minutes to decrypt the flag successfully**, and demonstrates the attack we have in mind. 

## Modifications
Due to using 2 of our 4 intended challenges for the final submission, we have refined the attack to be attacked in a very specific manner. The challengers will **only have access to the *sanitised server script*, and the *instructions* above**.

Furthermore, through our testing we have set the variables of the challenge to allow 6 attempts per session with at most 0.2s between queries to deter lazy bruteforcing of the system. Challengers will have to figure out these parameters through testing to break our system.s

The challengers will have to **understand the code** properly and the **poor modifications** made in order to smartly bruteforce the solution through CCA under the IND-CCA2 assumption in the given constraints. 