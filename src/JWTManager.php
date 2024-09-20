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

use ELLa123\HyperfJwt\Encoders\Base64UrlSafeEncoder;
use ELLa123\HyperfJwt\EncryptAdapters\PasswordHashEncrypter;
use ELLa123\HyperfJwt\Exceptions\InvalidTokenException;
use ELLa123\HyperfJwt\Exceptions\SignatureException;
use ELLa123\HyperfJwt\Exceptions\TokenBlacklistException;
use ELLa123\HyperfJwt\Exceptions\TokenExpiredException;
use ELLa123\HyperfJwt\Exceptions\TokenNotActiveException;
use ELLa123\HyperfJwt\Exceptions\TokenRefreshExpiredException;
use ELLa123\HyperfJwt\Interfaces\Encoder;
use ELLa123\HyperfJwt\Interfaces\Encrypter;
use Hyperf\Cache\Cache;
use Psr\SimpleCache\CacheInterface;
use Psr\SimpleCache\InvalidArgumentException;

class JWTManager
{
    /** 令牌有效时长 */
    protected int $ttl;

    /** 令牌有效刷新时长 */
    protected int $refreshTtl;

    /** 令牌过度时长 */
    protected int $transitionalTtl;

    protected Encrypter $encrypter;

    protected Encoder $encoder;

    protected CacheInterface $cache;

    protected array $drivers;

    protected string $secret;

    protected string $prefix;

    public function __construct(array $config)
    {
        $this->verifyConfig($config);

        $this->secret = $config['secret'];
        $this->drivers = $config['drivers'] ?? [];
        $this->prefix = $config['prefix'] ?? 'default';

        $this->resolveEncrypter($config['default'] ?? PasswordHashEncrypter::class);

        $this->encoder = $config['encoder'] ?? new Base64UrlSafeEncoder();
        // 获取缓存配置
        if (is_callable($config['cache'])) {
            $this->cache = call_user_func_array($config['cache'], []);
        } elseif (is_string($config['cache'])) {
            $this->cache = make($config['cache']);
        } elseif ($config['cache'] instanceof CacheInterface) {
            $this->cache = $config['cache'];
        } else {
            $this->cache = make(Cache::class);
        }
        $this->ttl = $config['ttl'] ?? 60 * 60 * 2;
        $this->refreshTtl = $config['refresh_ttl'] ?? 60 * 60 * 24 * 7; // 单位秒，默认一周内可以刷新
        $this->transitionalTtl = $config['transitional_ttl'] ?? 60 * 5; // 单位秒，默认五分钟内可以继续使用旧token
    }

    public function getTtl(): int
    {
        return $this->ttl;
    }

    public function getCache(): CacheInterface
    {
        if ($this->cache instanceof Cache) {
            return $this->cache;
        }

        return $this->cache = make(Cache::class);
    }

    /**
     * 单位：分钟
     * @return $this
     */
    public function setTtl(int $ttl): JWTManager
    {
        $this->ttl = $ttl;

        return $this;
    }

    public function getRefreshTtl(): int
    {
        return $this->refreshTtl;
    }

    public function getTransitionalTtl(): int
    {
        return $this->transitionalTtl;
    }

    /**
     * 单位：分钟
     * @return $this
     */
    public function setRefreshTtl(int $ttl): JWTManager
    {
        $this->refreshTtl = $ttl;

        return $this;
    }

    public function getEncrypter(): Encrypter
    {
        return $this->encrypter;
    }

    public function getEncoder(): Encoder
    {
        return $this->encoder;
    }

    /**
     * 创建一个 jwt.
     */
    public function make(array $payload, array $headers = []): JWT
    {
        $payload = array_merge($this->initPayload(), $payload);

        $jti = hash('md5', base64_encode(json_encode([$payload, $headers])) . $this->getEncrypter()->getSecret());

        $payload['jti'] = $jti;

        return new JWT($this, $headers, $payload);
    }

    /**
     * 一些基础参数.
     */
    public function initPayload(): array
    {
        $timestamp = time();

        return [
            'sub' => '1',
            'iss' => 'http://' . ($_SERVER['SERVER_NAME'] ?? '') . ':' . ($_SERVER['SERVER_PORT'] ?? '') . ($_SERVER['REQUEST_URI'] ?? ''),
            'exp' => $timestamp + $this->getTtl(), // 过期时间，表示令牌的有效截止时间。
            'iat' => $timestamp, // 令牌的签发时间，表示该令牌是什么时候被签发的。
            'nbf' => $timestamp, // 在此时间之前，令牌不能被接受处理
        ];
    }

    /**
     * 解析一个jwt.
     * @throws InvalidTokenException
     * @throws SignatureException
     * @throws TokenBlacklistException
     * @throws TokenExpiredException
     * @throws InvalidArgumentException|TokenNotActiveException
     */
    public function parse(string $token): JWT
    {
        $jwt = $this->justParse($token);
        $timestamp = time();
        $payload = $jwt->getPayload();

        if ($this->hasBlacklist($jwt)) {
            throw (new TokenBlacklistException('The token is already on the blacklist'))->setJwt($jwt);
        }

        if (isset($payload['exp']) && $payload['exp'] <= $timestamp) {
            throw (new TokenExpiredException('Token expired'))->setJwt($jwt);
        }

        if (isset($payload['nbf']) && $payload['nbf'] > $timestamp) {
            throw (new TokenNotActiveException('Token not active'))->setJwt($jwt);
        }

        return $jwt;
    }

    /**
     * 单纯的解析一个jwt.
     * @throws InvalidTokenException
     * @throws SignatureException
     */
    public function justParse(string $token): JWT
    {
        $encoder = $this->getEncoder();
        $encrypter = $this->getEncrypter();
        $arr = explode('.', $token);

        if (count($arr) !== 3) {
            throw new InvalidTokenException('Invalid token');
        }

        $headers = @json_decode($encoder->decode($arr[0]), true);
        $payload = @json_decode($encoder->decode($arr[1]), true);

        $signatureString = "{$arr[0]}.{$arr[1]}";

        if (! is_array($headers) || ! is_array($payload)) {
            throw new InvalidTokenException('Invalid token');
        }

        if ($encrypter->check($signatureString, $encoder->decode($arr[2]))) {
            return new JWT($this, $headers, $payload);
        }

        throw new SignatureException('Invalid signature');
    }

    /**
     * @throws InvalidArgumentException
     */
    public function addBlacklist(JWT|string $jwt): void
    {
        $now = time();
        $this->getCache()->set(
            $this->blacklistKey($jwt),
            $now,
            ($jwt instanceof JWT ? ($jwt->getPayload()['iat'] || $now) : $now) + $this->getRefreshTtl() // 存到该 token 超过 refresh 即可
        );
    }

    /**
     * @throws InvalidArgumentException
     */
    public function removeBlacklist(JWT|string $jwt): bool
    {
        return $this->getCache()->delete($this->blacklistKey($jwt));
    }

    /**
     * @throws InvalidArgumentException
     */
    public function hasBlacklist(JWT|string $jwt): bool
    {
        if (! $addTime = $this->getCache()->get($this->blacklistKey($jwt))) {
            return false;
        }

        return ($addTime + $this->getTransitionalTtl()) < time();
    }

    /**
     * @throws TokenRefreshExpiredException
     */
    public function refresh(JWT $jwt, bool $force = false): JWT
    {
        $payload = $jwt->getPayload();

        if (! $force && isset($payload['iat'])) {
            $refreshExp = $payload['iat'] + $this->getRefreshTtl();

            if ($refreshExp <= time()) {
                throw (new TokenRefreshExpiredException('token expired, refresh is not supported'))->setJwt($jwt);
            }
        }

        unset($payload['exp'], $payload['iat'], $payload['nbf']);

        return $this->make($payload, $jwt->getHeaders());
    }

    public function useEncrypter(string $encrypter): JWTManager
    {
        $this->resolveEncrypter($encrypter);
        return $this;
    }

    protected function blacklistKey(JWT|string $jwt): string
    {
        $jti = $jwt instanceof JWT ? ($jwt->getPayload()['jti'] ?? md5($jwt->token())) : md5($jwt);

        return "jwt:blacklist:{$this->prefix}:{$jti}";
    }

    protected function verifyConfig(array $config): void
    {
        if (! isset($config['secret'])) {
            throw new \InvalidArgumentException('Secret is required.');
        }
    }

    protected function resolveEncrypter($encrypter): void
    {
        if ($encrypter instanceof Encrypter) {
            $this->encrypter = $encrypter;
            return;
        }
        if (class_exists($encrypter)) {
            $this->encrypter = new $encrypter($this->secret);
            return;
        }
        if (isset($this->drivers[$encrypter])) {
            $encrypter = $this->drivers[$encrypter];
            $this->encrypter = new $encrypter($this->secret);
        } else {
            $this->encrypter = new PasswordHashEncrypter($this->secret);
        }
    }
}
