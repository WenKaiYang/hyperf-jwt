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

namespace ELLa123\HyperfJwt\Exceptions;

use ELLa123\HyperfJwt\JWT;

class JWTException extends \Exception
{
    /** @var JWT */
    protected $jwt;

    /**
     * @return static
     */
    public function setJwt(JWT $jwt)
    {
        $this->jwt = $jwt;

        return $this;
    }

    public function getJwt(): JWT
    {
        return $this->jwt;
    }
}
