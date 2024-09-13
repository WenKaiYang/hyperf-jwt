<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://hyperf.wiki
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf/hyperf/blob/master/LICENSE
 */

namespace ELLa123\HyperfJwt;

class JWT
{
    protected array $headers = [
        'typ' => 'jwt',
    ];

    protected array $payload = [];

    protected JWTManager $manager;

    /**
     * JWT constructor.
     */
    public function __construct(JWTManager $manager, array $headers, array $payload)
    {
        $this->manager = $manager;
        $this->headers = array_merge($this->headers, $headers);
        $this->payload = $payload;
    }

    public function token(): string
    {
        $signatureString = $this->generateSignatureString();

        $signature = $this->manager->getEncoder()->encode(
            $this->manager->getEncrypter()->signature($signatureString)
        );

        return "{$signatureString}.{$signature}";
    }

    public function generateSignatureString(): string
    {
        $headersString = $this->manager->getEncoder()->encode(json_encode($this->headers));
        $payloadString = $this->manager->getEncoder()->encode(json_encode($this->payload));

        return "{$headersString}.{$payloadString}";
    }

    public function getHeaders(): array
    {
        return $this->headers;
    }

    public function getPayload(): array
    {
        return $this->payload;
    }
}
