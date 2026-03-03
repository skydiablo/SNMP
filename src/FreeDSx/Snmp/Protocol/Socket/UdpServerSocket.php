<?php

declare(strict_types=1);

namespace FreeDSx\Snmp\Protocol\Socket;

use React\Datagram\Factory;

use function React\Async\await;

class UdpServerSocket implements ServerSocketInterface
{
    private \React\Datagram\Socket $socket;

    /**
     * @throws \Throwable
     */
    public function __construct(array $options)
    {
        $factory = new Factory(
            $options['loop'] ?? null,
            $options['resolver'] ?? null,
        );
        $this->socket = await(
            $factory->createServer(
                sprintf('%s:%d', $options['host'], (int)$options['port']),
            )
        );
//        $this->socket->bufferSize = 65507;
    }

    public function onData(callable $callback): ServerSocketInterface
    {
        $this->socket->on('message', $callback);

        return $this;
    }
}