<?php
declare(strict_types=1);

namespace FreeDSx\Snmp\Protocol\Socket;

use Evenement\EventEmitterInterface;
use React\Promise\PromiseInterface;

interface SocketInterface
{

    /**
     * Callback can fire multiple times for every data chunk
     * @param callable $callback
     * @return void
     */
    public function onData(callable $callback): self;

    /**
     * @param callable $callback
     * @return void
     */
    public function onError(callable $callback): self;

    /**
     * @param string $rawData
     * @return PromiseInterface
     */
    public function write(string $rawData): PromiseInterface;

    /**
     * Closes the transport connection associated with the client, if any.
     * @return void
     */
    public function close(): void;

}