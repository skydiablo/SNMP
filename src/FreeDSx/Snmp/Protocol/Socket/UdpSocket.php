<?php

declare(strict_types=1);

namespace FreeDSx\Snmp\Protocol\Socket;

use Evenement\EventEmitterTrait;
use React\Datagram\Socket as DatagramSocket;

use function React\Promise\resolve;

class UdpSocket implements SocketInterface
{

    protected DatagramSocket $socket;

    public function __construct(array $options)
    {
        /** @var DatagramSocket $socket */
        $socket = \React\Async\await(
            (new \React\Datagram\Factory())->createClient(
                sprintf('%s:%d', $options['host'], (int)$options['port']),
            ),
        );
        $this->socket = $socket;
        $this->socket->bufferSize = 65507;
    }


    /**
     * @param callable $callback params are $data, $peer, $socket
     *
     * @return void
     */
    public function onData(callable $callback): SocketInterface
    {
        $this->socket->on('message', $callback);
        return $this;
    }

    /**
     * @param callable $callback params are $e, $socket
     *
     * @return void
     */
    public function onError(callable $callback): SocketInterface
    {
        $this->socket->on('error', $callback);
        return $this;
    }


    public function write(string $rawData): \React\Promise\PromiseInterface
    {
        $this->socket->send($rawData);
        return resolve(true);
    }

    public function close(): void
    {
        $this->socket->close();
    }


}