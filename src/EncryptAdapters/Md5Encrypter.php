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

class Md5Encrypter extends AbstractEncrypter
{
    public function signature(string $signatureString): string
    {
        return hash('md5', $signatureString . $this->getSecret());
    }

    public static function alg(): string
    {
        return 'md5';
    }
}
