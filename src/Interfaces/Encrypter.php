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

namespace ELLa123\HyperfJwt\Interfaces;

interface Encrypter
{
    public function signature(string $signatureString): string;

    public function check(string $signatureString, string $signature): bool;

    public static function alg(): string;
}
