<?php

declare(strict_types=1);

namespace JwtTest;

require __DIR__ . '/vendor/autoload.php';

use DateTimeImmutable;
use DateTimeZone;
use Lcobucci\Clock\FrozenClock;
use Lcobucci\Clock\SystemClock;
use Lcobucci\JWT\Encoding\JoseEncoder;
use Lcobucci\JWT\Signer\Key;
use Lcobucci\JWT\Signer\Key\InMemory;
use Lcobucci\JWT\Signer\Rsa\Sha256;
use Lcobucci\JWT\Token;
use Lcobucci\JWT\Token\Parser;
use Lcobucci\JWT\UnencryptedToken;
use Lcobucci\JWT\Validation\Constraint;
use Lcobucci\JWT\Validation\ConstraintViolation;
use Lcobucci\JWT\Validation\Constraint\IssuedBy;
use Lcobucci\JWT\Validation\Constraint\LooseValidAt;
use Lcobucci\JWT\Validation\Constraint\SignedWith;
use Lcobucci\JWT\Validation\RequiredConstraintsViolated;
use Lcobucci\JWT\Validation\Validator;


$tokenString = $argv[1] ?? '';
if (empty($tokenString)) {
    echo "Please provide a token as the first argument\n";
    exit(1);
}

final class SigningCertMustBeSignedByRoot implements Constraint
{
    public function __construct(private Key $signingCert, private Key $certificateChain)
    {
    }

    public function assert(Token $token): void
    {
        if (!$token instanceof UnencryptedToken) {
            throw new ConstraintViolation('You should pass a plain token');
        }

        if (! $this->isSignedByRoot($token)) {
            throw new ConstraintViolation('Signing certificate is not signed by expected CA certificate');
        }
    }

    private function isSignedByRoot(Token $token): bool
    {
        $certificateChainFilename = tempnam(sys_get_temp_dir(), 'jwt-validate');
        file_put_contents($certificateChainFilename, $this->certificateChain->contents());
        $signingCertFilename = tempnam(sys_get_temp_dir(), 'jwt-validate');
        file_put_contents($signingCertFilename, $this->signingCert->contents());

        $certificateChainFilename = escapeshellarg($certificateChainFilename);
        $signingCertFilename = escapeshellarg($signingCertFilename);

        $cmd = "openssl verify -CAfile $certificateChainFilename $signingCertFilename";
        system($cmd, $result);

        return !$result;
    }
}

function extractFirstCertificate($chainFileName): string
{
    $content = file_get_contents($chainFileName);
    if ($content === false) {
        throw new Exception('Unable to read file.');
    }

    $certificates = explode("-----END CERTIFICATE-----\n", $content);

    return $certificates[0] . "-----END CERTIFICATE-----\n";
}



$parser = new Parser(new JoseEncoder());
$token = $parser->parse($tokenString);

$x5u = $token->headers()->get('x5u');
$signingCert = extractFirstCertificate(__DIR__ . '/' . $x5u);

$clock = new SystemClock(new \DateTimeZone('UTC'));
$clock = new FrozenClock(new DateTimeImmutable('2024-01-01 13:00:00', new DateTimeZone('UTC')));

$validator = new Validator();

$constraints = [
    new IssuedBy('https://app.example.com'),
    new LooseValidAt($clock),
    new SignedWith(new Sha256(), InMemory::plainText($signingCert)),
    new SigningCertMustBeSignedByRoot(InMemory::plainText($signingCert), InMemory::file(__DIR__ . '/' . $x5u)),
];

try {
    $validator->assert($token, ...$constraints);
    echo "**Valid Token**\n";
    echo "\nHeader:\n";
    print_r($token->headers()->all());
    echo "\nClaims:\n";
    print_r($token->claims()->all());
    echo "\n";
} catch (RequiredConstraintsViolated $e) {
    echo "**Invalid Token**\n";
    // list the failures
    foreach ($e->violations() as $violation) {
        echo "- " . $violation->getMessage() . "\n";
    }
    echo "\n";
} catch(\Throwable $e) {
    echo "An error occurred: " . $e->getMessage() . "\n";
}
