<?php
declare(strict_types=1);

namespace FreeDSx\Snmp\Protocol\Socket;

use React\Promise\PromiseInterface;

interface SocketInterface
{

    /**
     * Callback can fire multiple times for every data chunk
     * @param callable $callback
     * @return void
     */
    public function onData(callable $callback): void;

    /**
     * @param callable $callback
     * @return void
     */
    public function onError(callable $callback): void;

    /**
     * @param string $rawData
     * @return void
     */
    public function write(string $rawData): void;

    /**
     * Closes the transport connection associated with the client, if any.
     * @return void
     */
    public function close(): void;

}