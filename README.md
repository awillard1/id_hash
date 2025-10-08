# Example Usage
```
python3 id_hash/identify_hash.py --value-file id_hash/known.txt --hash-file id_hash/hash.txt --try-external --external-verbose --john-fork 28
```

# Ubuntu Directions

##### 1) System essentials (build tools only needed if a wheel isn’t available)
sudo apt update
sudo apt install -y python3 python3-pip python3-venv build-essential python3-dev libffi-dev

##### 2) External tools
sudo apt install -y hashcat john

##### 3) Python packages (local algs + extras used by the script)
python3 -m pip install --upgrade pip setuptools wheel
python3 -m pip install blake3 pycryptodome "passlib[bcrypt,argon2]" mmh3 xxhash

##### (Optional) If you ever had the old, incompatible PyCrypto:
python3 -m pip uninstall -y pycrypto

## Installing JTR
##### 1) Build deps (CPU-only)
sudo apt update
sudo apt install -y build-essential git pkg-config libssl-dev zlib1g-dev yasm \
                    libgmp-dev libpcap-dev libbz2-dev libzstd-dev libkrb5-dev

###### Optional (GPU/OpenCL support — if you have GPU drivers set up)
sudo apt install -y ocl-icd-opencl-dev opencl-headers

##### 2) Get source
git clone https://github.com/openwall/john.git
cd john/src

##### 3) Configure & build (CPU-only)
./configure
make -s clean && make -sj"$(nproc)"

##### 4) Symlink 'john' onto your PATH so you don’t need the full path (the compiled binary lives in ../run/john)
sudo ln -sf "$(pwd)/../run/john" /usr/local/bin/john

##### 5) Verify
john


## OpenSSL
Create a config (user-scoped is fine), e.g. ~/.config/openssl/openssl.cnf:

```
openssl_conf = openssl_init

[openssl_init]
providers = provider_sect

[provider_sect]
default = default_sect
legacy  = legacy_sect

[default_sect]
activate = 1

[legacy_sect]
activate = 1
```
