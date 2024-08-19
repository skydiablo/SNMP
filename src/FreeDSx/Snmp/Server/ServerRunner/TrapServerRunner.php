<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Server\ServerRunner;

use FreeDSx\Snmp\Protocol\Socket\ServerSocketInterface;
use FreeDSx\Snmp\Protocol\TrapProtocolHandler;

/**
 * Server for synchronous trap request handling.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class TrapServerRunner implements ServerRunnerInterface
{
    /**
     * @var array
     */
    protected array $options;

    /**
     * @var TrapProtocolHandler
     */
    protected TrapProtocolHandler $handler;

    /**
     * @param TrapProtocolHandler $handler
     * @param array               $options
     */
    public function __construct(
        TrapProtocolHandler $handler,
        array $options = [],
    ) {
        $this->options = $options;
        $this->handler = $handler;
    }

    /**
     * {@inheritdoc}
     */
    public function run(ServerSocketInterface $server): void
    {
        $server->onData(function (string $message, string $address, $server) {
            $this->handler->handle($address, $message, $this->options);
        });
    }
}
