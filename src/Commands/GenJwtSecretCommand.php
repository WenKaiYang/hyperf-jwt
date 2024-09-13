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

namespace ELLa123\HyperfJwt\Commands;

use Hyperf\Command\Annotation\Command;
use Hyperf\Command\Command as HyperfCommand;
use Hyperf\Utils\Str;

#[Command]
class GenJwtSecretCommand extends HyperfCommand
{
    protected $name = 'gen:jwt-secret';

    public function configure()
    {
        parent::configure();
        $this->setDescription('Create a new jwt secret');
    }

    public function handle(): void
    {
        $this->gen('JWT_SECRET');
    }

    public function gen($key, ?string $value = null): void
    {
        if (empty(env($key))) {
            file_put_contents(
                BASE_PATH . '/.env',
                sprintf(
                    PHP_EOL . '%s=%s',
                    $key,
                    $value ?? hash('sha256', Str::random(32))
                ),
                FILE_APPEND
            );
            $this->info($key . ' 已生成!');
        } else {
            $this->info($key . ' 已存在!');
        }
    }
}
