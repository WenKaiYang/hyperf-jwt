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

namespace ELLa123\HyperfJwt\EncryptAdapters;

use ELLa123\HyperfJwt\AbstractEncrypter;

class HS256Encrypter extends AbstractEncrypter
{
    public function signature(string $signatureString): string
    {
        return \hash_hmac('SHA256', $signatureString, $this->getSecret(), true);
    }

    public function check(string $signatureString, string $signature): bool
    {
        $hash = \hash_hmac('SHA256', $signatureString, $this->getSecret(), true);
        if (\function_exists('hash_equals')) {
            return \hash_equals($signature, $hash);
        }
        $len = \min(static::safeStrlen($signature), static::safeStrlen($hash));

        $status = 0;
        for ($i = 0; $i < $len; ++$i) {
            $status |= (\ord($signature[$i]) ^ \ord($hash[$i]));
        }
        $status |= (static::safeStrlen($signature) ^ static::safeStrlen($hash));

        return $status === 0;
    }

    public static function alg(): string
    {
        return 'HS256';
    }
}
