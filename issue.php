<?php

declare(strict_types=1);

namespace JwtTest;

require __DIR__ . '/vendor/autoload.php';

use DateTimeImmutable;
use Lcobucci\JWT\Configuration;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Signer\Key\InMemory;

use function var_dump;

$now = new DateTimeImmutable('2024-01-01 12:00:00');


$keyId = 'C945AD68-5494-43F2-8DB3-4CE5C9C51964';

// Create the chain
file_put_contents(
    __DIR__ . "/keys/$keyId.pem",
    file_get_contents(__DIR__ . '/keys/signing/one-i1.crt') . "\n"
    . file_get_contents(__DIR__ . '/keys/ca/intermediate-1.crt') . "\n"
    . file_get_contents(__DIR__ . '/keys/ca/root-ca.crt')
);
$chainUrl = "keys/$keyId.pem";

$configuration = Configuration::forAsymmetricSigner(
    new Sha256(),
    InMemory::file(__DIR__ . '/keys/signing/one-i1.pem'),
    InMemory::file(__DIR__ . '/keys/signing/one-i1.crt')
);
$builder = $configuration->builder()
    ->withHeader('x5u', $chainUrl)
    ->identifiedBy($keyId)
    ->issuedBy('https://app.example.com')
    ->issuedAt($now)
    ->expiresAt($now->modify('+6 hour'))
    ->withClaim('foo', 'bar');

$token = $builder->getToken($configuration->signer(), $configuration->signingKey());

echo "\nHeader:\n";
print_r($token->headers()->all());
echo "\n";

echo "\nClaims:\n";
print_r($token->claims()->all());
echo "\n";

echo "\nToken:\n";
echo $token->toString();
echo "\n";
