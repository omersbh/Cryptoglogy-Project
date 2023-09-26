# Cryptoglogy-Project



# The project topic
Secure files transmission app. Encryption-decryption by algorithm IDEA in CBC mode and Secure key delivery with Merkle–Hellman knapsack and ECDSA signature

# The project purpose
Our project purpose is to create a system for encryption and transmitting files in a safe manner while keeping principles of data security, and trying to avoid known weakness that can lead to a security breach like we've learned in the duration of the course.

# Preface
Without secure the files that we are sending to each other in our daily life, we are expose ourself to a lot of dangers, such as:
1) The files we are sending could be decrypted by unwanted third parties those resulting in data theft.
2) The files we are sending might be replaced with other files and if it would happen, we would want to know about that.
That's why we created that system.



# The system
The system is made up from 3 different sub-systems:

# IDEA in CBC mode: 
With a basic use of IDEA algorithm, we created our encryption and decryption system.
In the CBC mode we are dividing our input into blocks each one is 64-bit in size except from the last block that may be smaller.
We are using a 128-bit keys in each block, all the keys are the same.
We are encrypting each block with the previous encrypted block except from the first block that require an initial vector (IV) to encrypt it.

# Merkel-Hellman knapsack: 
The Merkel-Hellman algorithm generate 2 sets of keys, one is private and the other is public.
Both key size are 128-bit.
The private key is generated from a super increasing sequence of positive integers, and the public key is generated by choosing a multiplier and a modulus that are coprime to each other, then multiplying each element of the super increasing sequence by the multiplier and modulo the result with the modulus.

# ECDSA signature: 
We generate and verify our system signature with the ECDSA algorithm.
The algorithm creates a pair of keys, one private and other one public.
Then it chooses an elliptic curve and with a mathematical equation you represent the public key on the curve and save the private key securely.
The signature itself get another encryption using hashing.
The sender signing the file with he's private key, and sending the file.
And the receiver uses the public key to confirm that the signature is authentic,
and the file hasn't been replaced in the process. 
Together these three sub-systems used to encrypt and decrypt our transmission files app.

# Input/output:
The input is some type of a file and our output is an encrypted file.