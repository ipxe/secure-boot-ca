# iPXE Secure Boot CA

This repository holds the [CA certificate](ipxe-sb-ca.crt) used as the
embedded vendor certificate by the [iPXE shim][ipxeshim], along with
documentation to prove the provenance of the certificate.

## Hardware security module

The hardware security module used for this CA certificate is a
[YubiKey 5 NFC FIPS][yubikey] with serial number `02 04 01 b3 be f6`.

Slot `9a` on the HSM holds the [Extended Validation Code Signing
certificate](evcs.crt) issued by [SSL.com](https://ssl.com) and used
for the (initial) submission of the resulting shim to Microsoft for
Secure Boot signing.

Slot `9c` on the HSM is used for this CA certificate.

## Key pair

The command used to generate the CA key pair was:

	ykman piv keys generate --algorithm RSA2048 9c ipxe-sb-ca.pub

The resulting [public key](ipxe-sb-ca.pub) may be displayed using:

	openssl rsa -pubin -in ipxe-sb-ca.pub -noout -text

```
Public-Key: (2048 bit)
Modulus:
    00:ab:a8:a1:d2:73:ad:c2:1b:d8:01:b2:2f:67:6d:
    97:26:6f:de:e7:af:e6:56:c5:4b:b0:74:1b:39:ef:
    ca:33:0c:c9:b5:0b:9a:f4:38:cf:31:0d:a0:7d:97:
    6c:86:ff:e2:2f:0c:7c:a6:8c:fe:52:8b:5a:25:d6:
    2c:6b:59:2e:a5:b1:8d:e2:b7:05:c0:8f:1c:f5:1c:
    b0:69:15:8f:d8:23:65:4a:47:57:59:ed:b7:da:c7:
    22:d4:0f:65:2d:22:06:b0:07:14:8d:50:ae:69:87:
    b6:1c:88:81:ad:dc:4f:84:d4:2b:d4:7d:d9:d7:71:
    3f:fd:4d:cc:03:17:02:b1:e2:7a:55:f0:70:15:54:
    46:31:96:80:39:45:b8:21:e6:5d:07:40:b2:76:41:
    4a:17:06:8a:d0:80:8d:2a:92:8a:99:43:20:51:de:
    23:0d:af:60:37:35:45:c8:f8:4f:31:07:06:a5:c3:
    dd:ca:f7:28:32:20:16:e7:92:bb:95:1c:9a:34:ed:
    a8:26:9b:98:72:cd:45:55:11:95:eb:36:0e:73:a7:
    c3:d2:4e:4b:ef:ae:42:d1:5e:7c:8e:28:b8:e6:97:
    f3:48:4d:cd:fd:cc:99:e9:6e:d0:e5:47:4c:ee:8c:
    d2:53:f9:4c:fd:94:c2:47:70:74:36:06:ff:cc:f7:
    d0:75
Exponent: 65537 (0x10001)
```

## Attestation

An attestation certificate for the key pair was generated using:

	ykman piv keys attest 9c attestation-9c.crt

The resulting [attestation certificate](attestation-9c.crt) may be
displayed using:

	openssl x509 -in attestation-9c.crt -certopt ext_dump -noout -text

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            01:13:b5:58:32:2c:9e:80:21:58:09:97:c8:79:55:9e
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=Yubico PIV Attestation
        Validity
            Not Before: Mar 14 00:00:00 2016 GMT
            Not After : Apr 17 00:00:00 2052 GMT
        Subject: CN=YubiKey PIV Attestation 9c
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ab:a8:a1:d2:73:ad:c2:1b:d8:01:b2:2f:67:6d:
                    97:26:6f:de:e7:af:e6:56:c5:4b:b0:74:1b:39:ef:
                    ca:33:0c:c9:b5:0b:9a:f4:38:cf:31:0d:a0:7d:97:
                    6c:86:ff:e2:2f:0c:7c:a6:8c:fe:52:8b:5a:25:d6:
                    2c:6b:59:2e:a5:b1:8d:e2:b7:05:c0:8f:1c:f5:1c:
                    b0:69:15:8f:d8:23:65:4a:47:57:59:ed:b7:da:c7:
                    22:d4:0f:65:2d:22:06:b0:07:14:8d:50:ae:69:87:
                    b6:1c:88:81:ad:dc:4f:84:d4:2b:d4:7d:d9:d7:71:
                    3f:fd:4d:cc:03:17:02:b1:e2:7a:55:f0:70:15:54:
                    46:31:96:80:39:45:b8:21:e6:5d:07:40:b2:76:41:
                    4a:17:06:8a:d0:80:8d:2a:92:8a:99:43:20:51:de:
                    23:0d:af:60:37:35:45:c8:f8:4f:31:07:06:a5:c3:
                    dd:ca:f7:28:32:20:16:e7:92:bb:95:1c:9a:34:ed:
                    a8:26:9b:98:72:cd:45:55:11:95:eb:36:0e:73:a7:
                    c3:d2:4e:4b:ef:ae:42:d1:5e:7c:8e:28:b8:e6:97:
                    f3:48:4d:cd:fd:cc:99:e9:6e:d0:e5:47:4c:ee:8c:
                    d2:53:f9:4c:fd:94:c2:47:70:74:36:06:ff:cc:f7:
                    d0:75
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            1.3.6.1.4.1.41482.3.3:
                0000 - 05 04 03                                 ...

            1.3.6.1.4.1.41482.3.7:
                0000 - 02 04 01 b3 be f6                        ......

            1.3.6.1.4.1.41482.3.8:
                0000 - 03 01                                    ..

            1.3.6.1.4.1.41482.3.9:
                0000 - 81                                       .

    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        ab:93:3e:47:ca:75:a9:de:48:c7:f1:2a:50:16:64:a5:72:f4:
        47:18:b6:a8:30:b1:45:d4:62:fc:48:7e:e7:1a:8a:71:c3:d9:
        c4:44:7f:0a:0e:8a:d2:cd:70:9c:25:53:b6:6a:6b:b4:3c:b6:
        ed:b2:11:2f:ed:c1:1c:6a:2a:34:93:d1:ed:8c:01:eb:89:e9:
        6a:55:50:6f:54:9b:fe:59:46:35:06:f4:19:72:e0:5f:29:db:
        9e:c1:af:91:6f:96:af:44:b7:dc:31:ab:43:c0:4f:09:40:c3:
        be:74:6e:eb:94:e6:c7:58:4b:8a:78:63:51:56:65:30:4e:9c:
        aa:9e:c7:ff:2a:4f:d9:c4:8e:78:aa:75:90:fd:04:cf:48:fb:
        e2:f1:4c:4c:f7:54:c6:20:2d:be:8a:8c:50:1a:c7:66:dd:38:
        4a:f2:7e:ab:c2:d0:0f:58:58:20:db:9c:50:f2:66:b2:84:70:
        cc:e9:87:25:c5:03:32:ed:85:0f:be:6d:9e:1d:b9:94:ec:76:
        e2:5c:31:7b:01:21:fc:07:40:dd:fe:dc:17:3f:3a:3c:2d:8f:
        fc:ff:ff:b4:d1:94:28:1e:59:72:24:f2:61:ab:c3:e5:22:55:
        89:6f:d8:59:3a:be:67:da:c8:4c:bf:33:ae:30:3c:ce:a4:d4:
        04:49:9f:ba
```

As per the Yubico [attestation documentation][attestation], this
output shows the following details:

* Subject name includes the slot number (`9c`).

* Serial number of the Yubikey (extension OID `1.3.6.1.4.1.41482.3.7`)
  is `02 04 01 b3 be f6`.

* Form factor (extension OID `1.3.6.1.4.1.41482.3.9`) is `81`,
  representing a FIPS USB-A Keychain.

* PIN policy (first byte of extension OID `1.3.6.1.4.1.41482.3.8`) is
  `03`, representing "always required".

* Public key matches the public half of the generated [key
  pair](#key-pair).

## Verification

The intermediate attestation certificate was exported using:

	ykman piv certificates export f9 attestation-intermediate.crt

The Yubico [attestation root certificate][attestor] was downloaded
using:

	curl https://developers.yubico.com/PKI/yubico-piv-ca-1.pem \
		-o attestation-root.crt

and the full attestation chain can be verified using:

	openssl verify \
		-CAfile attestation-root.crt \
		-untrusted attestation-intermediate.crt \
		attestation-9c.crt

Note that for this verification to be meaningful, you should obtain
and independently verify your own copy of the Yubico [attestation root
certificate][attestor], rather than trusting the copy in this
repository.

This attestation verification proves that the private key [generated
above](#key-pair) was indeed generated on a Yubikey FIPS [hardware
security module](#hardware-security-module), and therefore cannot be
exported or otherwise cloned.

## Extended Validation

An attestation certificate for the key pair belonging to the [Extended
Validation Code Signing certificate](evcs.crt) in slot `9a` was
generated using:

	ykman piv keys attest 9a attestation-9a.crt

The resulting [attestation certificate](attestation-9a.crt) may be
displayed using:

	openssl x509 -in attestation-9a.crt -certopt ext_dump -noout -text

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            01:17:bd:cd:b9:47:ac:f3:e0:6f:c7:57:4a:44:05:dc
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=Yubico PIV Attestation
        Validity
            Not Before: Mar 14 00:00:00 2016 GMT
            Not After : Apr 17 00:00:00 2052 GMT
        Subject: CN=YubiKey PIV Attestation 9a
        Subject Public Key Info:
            Public Key Algorithm: id-ecPublicKey
                Public-Key: (256 bit)
                pub:
                    04:35:35:f2:eb:f0:0f:85:b3:a1:40:61:ed:52:33:
                    5b:1c:fe:fd:ea:dd:a9:f4:02:1f:45:1a:d2:54:3b:
                    9c:0b:2c:f5:46:bb:38:87:2d:5f:5f:40:63:ed:d3:
                    a4:72:29:49:13:f6:89:e2:56:4e:bf:c0:22:db:35:
                    f6:a8:26:c0:c0
                ASN1 OID: prime256v1
                NIST CURVE: P-256
        X509v3 extensions:
            1.3.6.1.4.1.41482.3.3:
                0000 - 05 04 03                                 ...

            1.3.6.1.4.1.41482.3.7:
                0000 - 02 04 01 b3 be f6                        ......

            1.3.6.1.4.1.41482.3.8:
                0000 - 02 01                                    ..

            1.3.6.1.4.1.41482.3.9:
                0000 - 81                                       .

    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        a2:4d:a3:32:e7:fa:6a:a3:81:17:d3:b4:34:e2:c8:27:b4:ea:
        f1:5f:d3:1b:95:b0:74:e4:ec:6a:c7:ec:67:30:0e:a8:b2:6b:
        c5:0f:4e:ed:af:13:9f:5a:ac:2f:e6:4d:0a:d7:9f:26:d1:c0:
        80:4c:6e:33:41:90:95:a2:e8:05:c1:42:65:ab:2e:e4:af:14:
        27:c4:51:a6:80:c1:66:40:7d:0a:83:3e:61:44:76:ed:e2:37:
        80:5d:17:8b:83:bd:a1:c0:a9:a3:a9:8b:57:29:f1:07:95:44:
        17:b9:5f:aa:de:8a:92:55:6c:a5:49:0a:a6:4b:d0:a9:0a:f1:
        15:7c:9e:75:ff:f3:f7:b7:9c:40:f9:55:bb:a4:bf:ce:a3:54:
        1f:48:7e:07:db:7b:54:e6:c5:0a:8f:f8:ba:06:5d:83:d6:6a:
        cf:b9:ff:98:90:55:fa:39:33:b1:6b:51:5a:0f:14:b6:b9:ad:
        ba:a8:c0:f1:de:28:44:a0:36:6c:f8:e5:6d:ef:88:ba:30:d7:
        81:3e:7c:44:91:a1:30:17:a9:41:b5:d1:86:16:7d:4b:c7:f3:
        c0:e3:b9:92:cb:e7:34:7e:aa:b0:1f:85:01:5f:ba:e1:0a:44:
        fc:5c:01:b4:86:40:c1:74:63:05:72:b4:79:90:61:f1:6b:e9:
        0e:50:36:d8
```

The full attestation chain can be verified using:

	openssl verify \
		-CAfile attestation-root.crt \
		-untrusted attestation-intermediate.crt \
		attestation-9a.crt

This attestation certificate shows the same Yubikey serial number (`02
04 01 b3 be f6`) as used for the [key pair](#key-pair) in slot `9c`.
This attestation verification therefore proves that the private key
was generated on the same Yubikey FIPS [hardware security
module](#hardware-security-module) used for the [Extended Validation
Code Signing certificate](evcs.crt), and therefore proves that the
Yubikey HSM holding this private key meets all of the requirements for
Extended Validation Code Signing, and is owned and controlled by [Fen
Systems Ltd.][fensystems] as the entity named in the Extended
Validation Code Signing certificate.

## Self-signing

A quirk of using the OpenSC PKCS#11 libraries with the Yubikey is that
private keys do not become visible and usable for signing until a
corresponding certificate exists in the slot.  A temporary self-signed
certificate was therefore created using:

	ykman piv certificates generate \
		-s "Temporary self-signed certificate" 9c ipxe-sb-ca.pub

This temporary self-signed certificate is never used: it exists only
to allow OpenSSL to perform signing of the real self-signed CA
certificate.

The CA certificate request was created using:

	ykman piv certificates request \
		-s "iPXE Secure Boot CA" 9c ipxe-sb-ca.pub ipxe-sb-ca.req

The final [CA certificate](ipxe-sb-ca.crt) was signed as per the
[configuration file](selfsign.cnf) using:

	openssl ca -config selfsign.cnf -selfsign \
		-in ipxe-sb-ca.req -out ipxe-sb-ca.crt -batch -notext

The resulting [CA certificate](ipxe-sb-ca.crt) may be displayed using:

	openssl x509 -in ipxe-sb-ca.crt -noout -text

```
Certificate:
    Data:
        Version: 3 (0x2)
        Serial Number:
            5d:98:da:a0:5d:69:64:0c:74:3c:eb:a8:c4:87:31:ec:77:20:73:37
        Signature Algorithm: sha256WithRSAEncryption
        Issuer: CN=iPXE Secure Boot CA
        Validity
            Not Before: Nov  6 16:04:16 2025 GMT
            Not After : Mar 24 16:04:16 2053 GMT
        Subject: CN=iPXE Secure Boot CA
        Subject Public Key Info:
            Public Key Algorithm: rsaEncryption
                Public-Key: (2048 bit)
                Modulus:
                    00:ab:a8:a1:d2:73:ad:c2:1b:d8:01:b2:2f:67:6d:
                    97:26:6f:de:e7:af:e6:56:c5:4b:b0:74:1b:39:ef:
                    ca:33:0c:c9:b5:0b:9a:f4:38:cf:31:0d:a0:7d:97:
                    6c:86:ff:e2:2f:0c:7c:a6:8c:fe:52:8b:5a:25:d6:
                    2c:6b:59:2e:a5:b1:8d:e2:b7:05:c0:8f:1c:f5:1c:
                    b0:69:15:8f:d8:23:65:4a:47:57:59:ed:b7:da:c7:
                    22:d4:0f:65:2d:22:06:b0:07:14:8d:50:ae:69:87:
                    b6:1c:88:81:ad:dc:4f:84:d4:2b:d4:7d:d9:d7:71:
                    3f:fd:4d:cc:03:17:02:b1:e2:7a:55:f0:70:15:54:
                    46:31:96:80:39:45:b8:21:e6:5d:07:40:b2:76:41:
                    4a:17:06:8a:d0:80:8d:2a:92:8a:99:43:20:51:de:
                    23:0d:af:60:37:35:45:c8:f8:4f:31:07:06:a5:c3:
                    dd:ca:f7:28:32:20:16:e7:92:bb:95:1c:9a:34:ed:
                    a8:26:9b:98:72:cd:45:55:11:95:eb:36:0e:73:a7:
                    c3:d2:4e:4b:ef:ae:42:d1:5e:7c:8e:28:b8:e6:97:
                    f3:48:4d:cd:fd:cc:99:e9:6e:d0:e5:47:4c:ee:8c:
                    d2:53:f9:4c:fd:94:c2:47:70:74:36:06:ff:cc:f7:
                    d0:75
                Exponent: 65537 (0x10001)
        X509v3 extensions:
            Authority Information Access:
                CA Issuers - URI:https://ipxe.org/secure-boot-ca
            X509v3 Authority Key Identifier:
                DC:7C:9C:1E:AF:7E:03:CA:B1:1C:60:5A:6D:18:27:22:60:90:97:A6
            X509v3 Basic Constraints: critical
                CA:TRUE
            X509v3 Extended Key Usage:
                Code Signing
            X509v3 Key Usage: critical
                Digital Signature, Certificate Sign, CRL Sign
            X509v3 Subject Key Identifier:
                DC:7C:9C:1E:AF:7E:03:CA:B1:1C:60:5A:6D:18:27:22:60:90:97:A6
    Signature Algorithm: sha256WithRSAEncryption
    Signature Value:
        78:21:3f:13:f9:08:61:29:1a:3a:97:b2:35:d8:20:2b:00:4b:
        9f:cd:f1:e6:23:2a:d8:e8:8c:d5:e6:f1:38:fd:e2:5f:a3:e5:
        9b:d5:1b:e4:3f:16:f6:c7:dc:4e:85:4c:2f:9b:15:65:2a:3e:
        10:84:0f:31:36:24:d0:2c:94:62:55:f9:21:f6:51:ec:a3:a8:
        dc:c4:71:b0:a5:5d:78:8f:b4:9c:bf:2c:38:27:1f:25:91:92:
        01:17:c2:f3:e4:13:8c:a6:c9:12:79:15:91:d9:c3:e5:1a:d8:
        b5:3d:c0:91:65:07:ee:d6:2c:04:64:2d:09:da:ac:a6:da:1b:
        78:12:1a:55:5d:01:2c:b2:15:c8:42:47:e4:96:b3:06:bf:5d:
        5c:89:09:ef:1f:e0:a9:6c:9f:31:ec:be:61:f5:90:2c:d4:1f:
        f0:9c:be:4f:dd:6b:1a:bb:a1:e2:6d:ac:35:ce:90:db:29:09:
        63:c9:78:83:dc:40:92:a4:f2:28:21:6f:ea:bc:97:be:0e:80:
        81:77:a0:38:f9:16:00:f5:e6:25:6e:00:4c:cb:8b:11:24:db:
        6d:b6:7a:cc:d7:cf:3d:a7:e8:10:b6:ff:be:68:8f:16:b2:ff:
        aa:b2:73:09:13:25:19:31:46:78:60:90:b9:9f:ee:01:27:80:
        cf:de:95:ec
```

The certificate's public key matches the key pair originally
[generated above](#key-pair).

## Finalisation

A [DER version](ipxe-sb-ca.der) of the CA certificate (as required for
embedding into shim) was created using:

	openssl x509 -in ipxe-sb-ca.crt -out ipxe-sb-ca.der -outform DER

The certificate was imported into the HSM (overwriting the temporary
self-signed certificate) using:

	ykman piv certificates import 9c ipxe-sb-ca.crt

The certificate's SHA-256 fingerprint may be obtained using:

	openssl x509 -in ipxe-sb-ca.crt -noout -sha256 -fingerprint

```
sha256 Fingerprint=D0:69:34:AB:DF:6A:7D:CF:E1:2C:F2:02:BC:0E:61:AC:BE:88:FF:F7:6E:78:9B:F8:52:38:8B:92:BC:39:79:FC
```

## Intermediate CAs

An intermediate CA certificate may be issued (on a **different**
Yubikey HSM) using command sequences such as:

	# Generate key and certificate request (using the intermediate CA's HSM)
	#
	ykman piv keys generate --algorithm RSA2048 9c ipxe-sb-int-g1a.pub
	ykman piv certificates request -s "iPXE Secure Boot Intermediate G1A" 9c \
		ipxe-sb-int-g1a.pub ipxe-sb-int-g1a.req

	# Sign certificate request (using the root CA's HSM)
	#
	openssl ca -config intermediate.cnf \
		-in ipxe-sb-int-g1a.req -out ipxe-sb-int-g1a.crt -batch -notext

	# Import intermediate CA certificate (using the intermediate CA's HSM)
	#
	ykman piv certificates import 9c ipxe-sb-int-g1a.crt

## Issuing

Code signing certificates may be issued using command sequences such
as:

	ykman piv keys generate --algorithm RSA2048 9d ipxe-sb-cs-g1a.pub

	ykman piv certificates request -s "iPXE Secure Boot Code Signing G1A" 9d \
		ipxe-sb-cs-g1a.pub ipxe-sb-cs-g1a.req

	openssl ca -config codesign.cnf \
		-in ipxe-sb-cs-g1a.req -out ipxe-sb-cs-g1a.crt -batch -notext

	ykman piv certificates import 9d ipxe-sb-cs-g1a.crt

## Signing

An iPXE binary may be signed using a command such as:

	osslsigncode sign -pkcs11module /usr/lib64/opensc-pkcs11.so \
		-pkcs11cert 'pkcs11:id=%03' -key 'pkcs11:id=%03' \
		-certs ipxe-sb-int-g1a.crt \
		-ts http://timestamp.digicert.com \
		-in snponly.efi -out snponly-signed.efi

and verified using a command such as:

	osslsigncode verify -CAfile ipxe-sb-ca.crt snponly-signed.efi

[ipxeshim]: https://github.com/ipxe/shim
[yubikey]: https://www.yubico.com/store/yubikey-5-fips-series
[attestation]: https://developers.yubico.com/PIV/Introduction/PIV_attestation.html
[attestor]: https://developers.yubico.com/PKI/yubico-piv-ca-1.pem
[fensystems]: https://www.fensystems.co.uk/
