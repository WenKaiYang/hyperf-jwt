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

namespace ELLa123\HyperfJwt\Encoders;

use ELLa123\HyperfJwt\Interfaces\Encoder;

class Base64UrlSafeEncoder implements Encoder
{
    public function encode(string $string): string
    {
        return rtrim(strtr(base64_encode($string), '+/', '-_'), '=');
    }

    public function decode(string $string): string
    {
        return base64_decode(strtr($string, '-_', '+/'));
    }
}
