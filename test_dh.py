from dh import *
a, b = generate_private_key(), generate_private_key()
A, B = compute_public_key(a), compute_public_key(b)
assert compute_shared_secret(B, a) == compute_shared_secret(A, b)
assert derive_keys(compute_shared_secret(B, a)) == derive_keys(compute_shared_secret(A, b))
print("DH symmetry holds")