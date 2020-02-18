from field import FieldElement
from polynomial import X
from polynomial import interpolate_poly
from hashlib import sha256
from hashlib import sha256
from channel import serialize
from channel import Channel
from field import FieldElement
from merkle import MerkleTree
from polynomial import interpolate_poly, X, prod
from polynomial import interpolate_poly, Polynomial
from hashlib import sha256
import time



# a STARK proving mechanism 
# from StarkWare101 Workshop
# in San Fransisco, 2/17/20


##########
# PART 1 #
##########

# first step is to create a list of length 1023 
# first two elements are FieldElement objects 
# representing 1 and 3141592 respectively.

a = [FieldElement(1), FieldElement(3141592)]
while len(a) < 1023:
    a.append(a[-2] * a[-2] + a[-1] * a[-1])

# quick unit test to verify a[] constructed properly
assert len(a) == 1023, 'The trace must consist of exactly 1023 elements.'
assert a[0] == FieldElement(1), 'The first element in the trace must be the unit element.'
for i in range(2, 1023):
    assert a[i] == a[i - 1] * a[i - 1] + a[i - 2] * a[i - 2], f'The FibonacciSq recursion rule does not apply for index {i}'
assert a[1022] == FieldElement(2338775057), 'Wrong last element!'
print('Success!')

# need a generator from field element class
# need to generator a group of size 1024

g = FieldElement.generator() ** (3 * 2 ** 20)
G = [g ** i for i in range(1024)]

# need to construct a polynomial
# using X from polynomial package
# quick test: p = x^2 + 1

p = 2 * X ** 2 + 1

#can evaluate p at 2 by the following:
print(p(2))
p


#create v such that v will contain a value of the field 
# f at FieldElement(2)
f = interpolate_poly(G[:-1], a)
v = f(2)

assert v == FieldElement(1302089273)
print('Success!')



#need to make sure that the the element of h are powers of its generator in 
# order, that is - H[0] will be the unit, H[1] will be h (H's generator), H[2] will be H's
# generator squared, etc.

w = FieldElement.generator()
h = w ** ((2 ** 30 * 3) // 8192)
H = [h ** i for i in range(8192)]
eval_domain = [w * x for x in H]


#unit test
assert len(set(eval_domain)) == len(eval_domain)
w = FieldElement.generator()
w_inv = w.inverse()
assert '55fe9505f35b6d77660537f6541d441ec1bd919d03901210384c6aa1da2682ce' == sha256(str(H[1]).encode()).hexdigest(),\
    'H list is incorrect. H[1] should be h (i.e., the generator of H).'
for i in range(8192):
    assert ((w_inv * eval_domain[1]) ** i) * w == eval_domain[i]
print('Success!')

# evaluate on a coset. use interpolate package
f = interpolate_poly(G[:-1], a)
f_eval = [f(d) for d in eval_domain]

# Test against a precomputed hash.
from hashlib import sha256
from channel import serialize
assert '1d357f674c27194715d1440f6a166e30855550cb8cb8efeb72827f6a1bf9b5bb' == sha256(serialize(f_eval).encode()).hexdigest()
print('Success!')


# Commitments
from merkle import MerkleTree
f_merkle = MerkleTree(f_eval)
assert f_merkle.root == '6c266a104eeaceae93c14ad799ce595ec8c2764359d7ad1b4b7c57a4da52be04'
print('Success!')

# Channel
# need to reduce using Fiat-Shamir. This converts to non-interactive
from channel import Channel
channel = Channel()
channel.send(f_merkle.root)


# print proof generated so far
print(channel.proof)



##########
# PART 2 #
##########

# establishing constraints. need to have u(x) such that it is divisible.

numer0 = f - 1
denom0 = X - 1


# need to show that for first constraint, this will result in 0
# indicating that polynomial has roots and is divisible
numer0 % denom0

# define p0 to be first constraint
p0 = numer0 / denom0

#quick unit test to ensure accuracy
assert p0(2718) == 2509888982
print('Success!')


# need to define second constraint

numer1 = f - 2338775057
denom1 = X - g ** 1022

p1 = numer1 / denom1

# test p1 
assert p1(5772) == 232961446
print('Success!')

# if successful, p1 is now second constraint.

# need to define 3rd constraint
# start by constructing a list `lst` of the linear terms (x-g**i):
lst = [(X - g**i) for i in range(1024)]
prod(lst)


# define 3rd constraint such that it is f composed with g
numer2 = f(g**2 * X) - f(g * X)**2 - f**2
print("Numerator at g^1020 is", numer2(g**1020))
print("Numerator at g^1021 is", numer2(g**1021))
denom2 = (X**1024 - 1) / ((X - g**1021) * (X - g**1022) * (X - g**1023))

p2 = numer2 / denom2

assert p2.degree() == 1023, f'The degree of the third constraint is {p2.degree()} when it should be 1023.'
assert p2(31415) == 2090051528
print('Success!')


# observe degrees of constraint polynomials
print('deg p0 =', p0.degree())
print('deg p1 =', p1.degree())
print('deg p2 =', p2.degree())



# need to create a succint proof by combing the 3 constraint polynomials
# into random linear combination which will refer to as the composition
# polynomial
def get_CP(channel):
    alpha0 = channel.receive_random_field_element()
    alpha1 = channel.receive_random_field_element()
    alpha2 = channel.receive_random_field_element()
    return alpha0*p0 + alpha1*p1 + alpha2*p2




#quick test
test_channel = Channel()
CP_test = get_CP(test_channel)
assert CP_test.degree() == 1023, f'The degree of cp is {CP_test.degree()} when it should be 1023.'
assert CP_test(2439804) == 838767343, f'cp(2439804) = {CP_test(2439804)}, when it should be 838767343'
print('Success!')


# evaluate cp over the evaluation domain (eval_domain), 
# build a Merkle tree on top of that and send its root over the channel

def CP_eval(channel):
    CP = get_CP(channel)
    return [CP(d) for d in eval_domain]


# Construct a Merkle Tree over the evaluation and 
# send its root over the channel.

channel = Channel()
CP_merkle = MerkleTree(CP_eval(channel))
channel.send(CP_merkle.root)

# last test
assert CP_merkle.root == 'a8c87ef9764af3fa005a1a2cf3ec8db50e754ccb655be7597ead15ed4a9110f1', 'Merkle tree root is wrong.'
print('Success!')




##########
# PART 3 #
##########

# need a function that take a domain as an argument
# and returns the next one
def next_fri_domain(fri_domain):
    return [x ** 2 for x in fri_domain[:len(fri_domain) // 2]]

# Test against a precomputed hash.

next_domain = next_fri_domain(eval_domain)
assert '5446c90d6ed23ea961513d4ae38fc6585f6614a3d392cb087e837754bfd32797' == sha256(','.join([str(i) for i in next_domain]).encode()).hexdigest()
print('Success!')



# need a function that takes a polynomial and a field element beta
# as arguments and returns "folded" next polynomial. 

def next_fri_polynomial(poly,  beta):
    odd_coefficients = poly.poly[1::2]
    even_coefficients = poly.poly[::2]
    odd = beta * Polynomial(odd_coefficients)
    even = Polynomial(even_coefficients)
    return odd + even



#need a fucntion that takes a polynomial, a domain, and a field element (again -  β), and returns the next polynomial, 
#the next domain, and the evaluation of this next polynomial on this next domain.

def next_fri_layer(poly, domain, beta):
    next_poly = next_fri_polynomial(poly, beta)
    next_domain = next_fri_domain(domain)
    next_layer = [next_poly(x) for x in next_domain]
    return next_poly, next_domain, next_layer



#test fri layer
test_poly = Polynomial([FieldElement(2), FieldElement(3), FieldElement(0), FieldElement(1)])
test_domain = [FieldElement(3), FieldElement(5)]
beta = FieldElement(7)
next_p, next_d, next_l = next_fri_layer(test_poly, test_domain, beta)
assert next_p.poly == [FieldElement(23), FieldElement(7)]
assert next_d == [FieldElement(9)]
assert next_l == [FieldElement(86)]
print('Success!')


# generate a fri commitment
def FriCommit(cp, domain, cp_eval, cp_merkle, channel):    
    fri_polys = [cp]
    fri_domains = [domain]
    fri_layers = [cp_eval]
    fri_merkles = [cp_merkle]
    while fri_polys[-1].degree() > 0:
        beta = channel.receive_random_field_element()
        next_poly, next_domain, next_layer = next_fri_layer(fri_polys[-1], fri_domains[-1], beta)
        fri_polys.append(next_poly)
        fri_domains.append(next_domain)
        fri_layers.append(next_layer)
        fri_merkles.append(MerkleTree(next_layer))
        channel.send(fri_merkles[-1].root)   
    channel.send(str(fri_polys[-1].poly[0]))
    return fri_polys, fri_domains, fri_layers, fri_merkles



##########
# PART 4 #
##########

from tutorial_sessions import part1, part3 

_, _, _, _, _, _, _, f_eval, f_merkle, _ = part1()
fri_polys, fri_domains, fri_layers, fri_merkles, _ = part3()


def decommit_on_fri_layers(idx, channel):
    for layer, merkle in zip(fri_layers[:-1], fri_merkles[:-1]):
        length = len(layer)
        idx = idx % length
        sib_idx = (idx + length // 2) % length        
        channel.send(str(layer[idx]))
        channel.send(str(merkle.get_authentication_path(idx)))
        channel.send(str(layer[sib_idx]))
        channel.send(str(merkle.get_authentication_path(sib_idx)))       
    channel.send(str(fri_layers[-1][0]))


def decommit_on_query(idx, channel): 
    assert idx + 16 < len(f_eval), f'query index: {idx} is out of range. Length of layer: {len(f_eval)}.'
    channel.send(str(f_eval[idx])) # f(x).
    channel.send(str(f_merkle.get_authentication_path(idx))) # auth path for f(x).
    channel.send(str(f_eval[idx + 8])) # f(gx).
    channel.send(str(f_merkle.get_authentication_path(idx + 8))) # auth path for f(gx).
    channel.send(str(f_eval[idx + 16])) # f(g^2x).
    channel.send(str(f_merkle.get_authentication_path(idx + 16))) # auth path for f(g^2x).
    decommit_on_fri_layers(idx, channel)   




# Test against a precomputed hash.
test_channel = Channel()
for query in [8134, 1110, 1134, 6106, 7149, 4796, 144, 4738, 957]:
    decommit_on_query(query, test_channel)
assert test_channel.state == '16a72acce8d10ffb318f8f5cd557930e38cdba236a40439c9cf04aaf650cfb96', 'State of channel is wrong.'
print('Success!')



def decommit_fri(channel):
    for query in range(3):
        # Get a random index from the verifier and send the corresponding decommitment.
        decommit_on_query(channel.receive_random_int(0, 8191-16), channel)

test_channel = Channel()
decommit_fri(test_channel)
assert test_channel.state == 'eb96b3b77fe6cd48cfb388467c72440bdf035c51d0cfe8b4c003dd1e65e952fd', 'State of channel is wrong.' 
print('Success!')





start = time.time()
start_all = start
print("Generating the trace...")
_, _, _, _, _, _, _, f_eval, f_merkle, _ = part1()
print(f'{time.time() - start}s')
start = time.time()
print("Generating the composition polynomial and the FRI layers...")
fri_polys, fri_domains, fri_layers, fri_merkles, channel = part3()
print(f'{time.time() - start}s')
start = time.time()
print("Generating queries and decommitments...")
decommit_fri(channel)
print(f'{time.time() - start}s')
start = time.time()
print(channel.proof)
print(f'Overall time: {time.time() - start_all}s')
print(f'Uncompressed proof length in characters: {len(str(channel.proof))}')