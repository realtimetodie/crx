# test

Create a RSA private key

```
$ openssl genrsa -out rsa2048-key.pem 2048
```

Create a EC private key using the NIST P-256 curve

```
$ openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -pkeyopt ec_param_enc:named_curve -out ec256-key.pem
```
