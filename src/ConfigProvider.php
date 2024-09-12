<?php

declare(strict_types=1);
/**
 * This file is part of Hyperf.
 *
 * @link     https://www.hyperf.io
 * @document https://doc.hyperf.io
 * @contact  group@hyperf.io
 * @license  https://github.com/hyperf/hyperf/blob/master/LICENSE
 */

namespace ELLa123\HyperfJwt;

use ELLa123\HyperfJwt\Commands\GenJwtSecretCommand;

class ConfigProvider
{
    public function __invoke(): array
    {
        return [
            'dependencies' => [
            ],
            'commands' => [
                GenJwtSecretCommand::class,
            ],
            'annotations' => [
                'scan' => [
                    'paths' => [
                        __DIR__,
                    ],
                ],
            ],
            'publish' => [
                [
                    'id' => 'jwt',
                    'description' => 'jwt 配置文件。', // 描述
                    // 建议默认配置放在 publish 文件夹中，文件命名和组件名称相同
                    'source' => __DIR__ . '/../publish/config/jwt.php',  // 对应的配置文件路径
                    'destination' => BASE_PATH . '/config/autoload/jwt.php', // 复制为这个路径下的该文件
                ],
            ],
        ];
    }
}
