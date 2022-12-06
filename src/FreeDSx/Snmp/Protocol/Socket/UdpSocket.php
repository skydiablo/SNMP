<?php
declare(strict_types=1);

namespace FreeDSx\Snmp\Protocol\Socket;

use React\Datagram\Socket;

class UdpSocket implements SocketInterface
{

    protected Socket $socket;

    public function __construct(array $options)
    {
        $factory = new \React\Datagram\Factory();
        $this->socket = \React\Async\await(
            $factory->createClient(sprintf('%s:%d', $options['host'], (int)$options['port']))
        );
        $this->socket->bufferSize = 65507;
    }


    /**
     * @param callable $callback params are $data, $peer, $socket
     * @return void
     */
    public function onData(callable $callback): void
    {
        $this->socket->on('message', $callback);
    }

    /**
     * @param callable $callback params are $e, $socket
     * @return void
     */
    public function onError(callable $callback): void
    {
        $this->socket->on('error', $callback);
    }


    public function write(string $rawData): void
    {
        $this->socket->send($rawData);
    }

    public function close(): void
    {
        $this->socket->close();
    }


}