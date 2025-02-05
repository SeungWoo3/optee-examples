#!/bin/bash

# [T194 example]
# This is default KEK2 root key for unfused board
echo "00000000000000000000000000000000" > kek2.key

# This is the fixed vector for deriving EKB root key from fuse.
# It is expected user to replace the FV below with a user specific
# FV, and code the exact same user specific FV into OP-TEE.
echo "bad66eb4484983684b992fe54a648bb8" > fv_ekb_t194

# Generate user-defined symmetric key files
# For each key, uncomment the random generate key and comment out the next line for production
# openssl rand -rand /dev/urandom -hex 16 > sym_t194.key
echo "00000000000000000000000000000000" > sym_t194.key
# openssl rand -rand /dev/urandom -hex 16 > sym2_t194.key
echo "00000000000000000000000000000000" > sym2_t194.key
# openssl rand -rand /dev/urandom -hex 16 > auth_t194.key
echo "00000000000000000000000000000000" > auth_t194.key

python3 gen_ekb.py -chip t194 -kek2_key kek2.key \
        -fv fv_ekb_t194 \
        -in_sym_key sym_t194.key \
        -in_sym_key2 sym2_t194.key \
        -in_auth_key auth_t194.key \
        -out eks_t194.img

# [T234 example]
# Fill your OEM_K1 fuse key value
echo "2d4a614e645267556b58703273357638792f423f4428472b4b6250655368566d" > oem_k1.key

# This is the fixed vector for deriving EKB root key from fuse.
# It is expected user to replace the FV below with a user specific
# FV, and code the exact same user specific FV into OP-TEE.
echo "bad66eb4484983684b992fe54a648bb8" > fv_ekb_t234

# Generate user-defined symmetric key files
# For each key, uncomment the random generate key and comment out the next line for production
# openssl rand -rand /dev/urandom -hex 32 > sym_t234.key    # kernel/kernel-dtb encryption key
echo "0000000000000000000000000000000000000000000000000000000000000000" > sym_t234.key
# openssl rand -rand /dev/urandom -hex 16 > sym2_t234.key   # disk encryption key
echo "f0e0d0c0b0a001020304050607080900" > sym2_t234.key
# openssl rand -rand /dev/urandom -hex 16 > auth_t234.key   # uefi variables authentication key
echo "d9f7b49e3b6264985f1326f541bb43c9" > auth_t234.key

python3 gen_ekb.py -chip t234 -oem_k1_key oem_k1.key \
        -fv fv_ekb_t234 \
        -in_sym_key sym_t234.key \
        -in_sym_key2 sym2_t234.key \
        -in_auth_key auth_t234.key \
        -in_device_id device_id_cert.der \
        -in_ftpm_sn 00000000000000000000 \
        -in_ftpm_eps_seed ftpm_eps_seed_file \
        -in_ftpm_rsa_ek_cert ftpm_rsa_ek_cert.der \
        -in_ftpm_ec_ek_cert ftpm_ec_ek_cert.der \
        -out eks_t234.img
