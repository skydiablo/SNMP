<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp;

use FreeDSx\Snmp\Protocol\Socket\ServerSocketInterface;
use FreeDSx\Snmp\Protocol\Socket\UdpServerSocket;
use FreeDSx\Snmp\Protocol\TrapProtocolHandler;
use FreeDSx\Snmp\Server\ServerRunner\TrapServerRunner;
use FreeDSx\Snmp\Server\ServerRunner\ServerRunnerInterface;
use FreeDSx\Snmp\Trap\TrapListenerInterface;

/**
 * Trap Sink to receive SNMP traps from remote hosts and take action on them.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class TrapSink
{
    /**
     * @var array
     */
    protected array $options
        = [
            # The IP address to bind to
            'host'            => '0.0.0.0',
            # The port that the traps will come in on
            'port'            => 162,
            'transport'       => 'udp',
            # If specified, only allow this SNMP version.
            'version'         => null,
            # If specified, only allow traps with this community string
            'community'       => null,
            # If specified, only these IPs are allowed (array or single IP)
            'whitelist'       => null,
            'timeout_connect' => 5,
        ];

    /**
     * @var TrapServerRunner|null
     */
    protected ?TrapServerRunner $server;

    /**
     * @var TrapListenerInterface
     */
    protected TrapListenerInterface $listener;

    /**
     * @param TrapListenerInterface $listener
     * @param array                 $options
     */
    public function __construct(
        TrapListenerInterface $listener,
        array $options = []
    ) {
        $this->options = array_merge($this->options, $options);
        $this->listener = $listener;
    }

    /**
     * Start listening for traps.
     */
    public function listen(?ServerSocketInterface $serverSocket = null): void
    {
        $this->server()->run(
            $serverSocket ?? $this->createSocketServer(),
        );
    }

    protected function createSocketServer(): ServerSocketInterface
    {
        switch ($this->options['transport']) {
            case 'udp':
                return new UdpServerSocket($this->options);
            default:
                throw new \InvalidArgumentException(
                    sprintf(
                        'Not supported transport type "%s", yet!',
                        $this->options['transport'],
                    ),
                );
        }
    }

    /**
     * @return array
     */
    public function getOptions(): array
    {
        return $this->options;
    }

    /**
     * @param array $options
     *
     * @return $this
     */
    public function setOptions(array $options): TrapSink
    {
        $this->options = array_merge($this->options, $options);

        return $this;
    }

    /**
     * @param TrapServerRunner $server
     *
     * @return $this
     */
    public function setServer(TrapServerRunner $server): TrapSink
    {
        $this->server = $server;

        return $this;
    }

    /**
     * @return ServerRunnerInterface
     */
    protected function server(): ServerRunnerInterface
    {
        if (!$this->server) {
            $this->server = new TrapServerRunner(
                new TrapProtocolHandler($this->listener, $this->options),
                $this->options,
            );
        }

        return $this->server;
    }
}
