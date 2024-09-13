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

class PasswordHashEncrypter extends AbstractEncrypter
{
    public function signature(string $signatureString): string
    {
        return password_hash(md5($signatureString . $this->getSecret()), PASSWORD_BCRYPT);
    }

    public function check(string $signatureString, string $signature): bool
    {
        return password_verify(md5($signatureString . $this->getSecret()), $signature);
    }

    public static function alg(): string
    {
        return 'bcrypt';
    }
}
