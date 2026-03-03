<?php

declare(strict_types=1);

namespace FreeDSx\Snmp\Protocol\Socket;

interface ServerSocketInterface
{
    /**
     * @param callable $callback The callback to call when a new data is received.
     *                           string $message, string $address, $server are passed to the callback
     *
     * @return self
     */
    public function onData(callable $callback): self;
}