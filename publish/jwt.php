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
use ELLa123\HyperfJwt\Encoders;
use ELLa123\HyperfJwt\EncryptAdapters as Encrypter;
use Hyperf\Cache\Cache;

return [
    /*
     * 必填
     * jwt 服务端身份标识
     */
    'secret' => env('JWT_SECRET', ''),

    /*
     * 可选配置
     * jwt 生命周期，单位秒，默认一天
     */
    'ttl' => env('JWT_TTL', 60 * 60 * 24),

    /*
     * 可选配置
     * 允许过期多久以内的 token 进行刷新，默认一周
     */
    'refresh_ttl' => env('JWT_REFRESH_TTL', 60 * 60 * 24 * 7),

    /*
     * 可选配置
     * 允许多就以内的 token 失效还访问，默认五分钟
     */
    'transitional_ttl' => env('JWT_TRANSITIONAL_TTL', 60 * 5),

    /*
     * 可选配置
     * 默认使用的加密类
     */
    'default' => Encrypter\PasswordHashEncrypter::class,

    /*
     * 可选配置
     * 加密类必须实现 ELLa123\HyperfJwt\Interfaces\Encrypter 接口
     */
    'drivers' => [
        Encrypter\PasswordHashEncrypter::alg() => Encrypter\PasswordHashEncrypter::class,
        Encrypter\CryptEncrypter::alg() => Encrypter\CryptEncrypter::class,
        Encrypter\SHA1Encrypter::alg() => Encrypter\SHA1Encrypter::class,
        Encrypter\Md5Encrypter::alg() => Encrypter\Md5Encrypter::class,
        Encrypter\HS256Encrypter::alg() => Encrypter\HS256Encrypter::class,
    ],

    /*
     * 可选配置
     * 编码类
     */
    'encoder' => new Encoders\Base64UrlSafeEncoder(),

    /*
     * 可选配置
     * 缓存类，用于黑名单
     */
    'cache' => function () {
        return make(Cache::class);
    },

    /*
     * 可选配置
     * 缓存前缀
     */
    'prefix' => env('JWT_CACHE_PREFIX', 'jwt'),
];
