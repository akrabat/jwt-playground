# JWT signing playground

Just some code to play around with JWTs signed by certs that have a
chain-of-trust. Do not use in production.


# Notes

1. `./generate-root-ca.sh` generates a couple of root CAs and a couple of
   intermediate CAs for each one.
2. `./generate-cert.sh` generates two certs, one each signed by the first
   intermediate CA of each root CA.
3. `php issue.php` will create a JWT.
4. `php validate.php` will validate a JWT. This also has a custom
    `SigningCertMustBeSignedByRoot` constraint that checks the chain of trust.
