<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Protocol;

use FreeDSx\Snmp\Exception\ConnectionException;
use FreeDSx\Snmp\Protocol\Factory\SecurityModelModuleFactory;
use FreeDSx\Snmp\Protocol\Socket\SocketInterface;
use FreeDSx\Snmp\Protocol\Socket\UdpSocket;
use FreeDSx\Snmp\Request\RequestInterface;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Response\ResponseInterface;

/**
 * Some common protocol handler functionality.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
trait ProtocolTrait
{
    use IdGeneratorTrait;

    /**
     * @var null|SocketInterface
     */
    protected $socket;

    /**
     * @var null|SnmpEncoder
     */
    protected $encoder;

    /**
     * @var SecurityModelModuleFactory
     */
    protected $securityModelFactory;

    /**
     * Maps allowed response PDUs for the SNMP version.
     *
     * @var int[][]
     */
    protected $allowedResponses = [
        0 => [
            2,
        ],
        1 => [
            2,
            8
        ],
        3 => [
            2,
            8,
        ],
    ];

    /**
     * Maps allowed request PDUs for
     * @var int[][]
     */
    protected $allowedRequests = [
        0 => [
            0,
            1,
            3,
            4,
        ],
        1 => [
            0,
            1,
            3,
            5,
            6,
            7,
        ],
        3 => [
            0,
            1,
            3,
            5,
            6,
            7,
        ],
    ];

    /**
     * @var array
     */
    protected $versionMap = [
        0 => 1,
        1 => 2,
        3 => 3,
    ];

    /**
     * Needed to set the ID in the PDU. Unfortunately the protocol designers put the ID for the overall message inside
     * of the PDU (essentially the request / response objects). This made it awkward to work with when separating the
     * logic of the ID generation /message creation. Maybe a better way to handle this in general?
     *
     * @param RequestInterface|ResponseInterface|TrapV1Request $pdu
     */
    protected function setPduId($pdu, int $id): void
    {
        if (!($pdu instanceof RequestInterface || $pdu instanceof ResponseInterface)) {
            return;
        }
        # The Trap v1 PDU has no request ID associated with it.
        if ($pdu instanceof TrapV1Request) {
            return;
        }
        $requestObject = new \ReflectionObject($pdu);
        $idProperty = $requestObject->getProperty('id');
        $idProperty->setAccessible(true);
        $idProperty->setValue($pdu, $id);
    }

    protected function isRequestAllowed(int $version, int $request): bool
    {
        return \in_array($request, $this->allowedRequests[$version], true);
    }

    /**
     * @param array $options
     * @return \React\Promise\PromiseInterface<\React\Datagram\Socket>
     * @throws ConnectionException
     */
    protected function socket(array $options = []): \React\Promise\PromiseInterface
    {
        if ($this->socket) {
            return \React\Promise\resolve($this->socket);
        } else {
            $options += $this->options;
            try {
                if ($options['transport'] !== 'udp') {
                    throw new \InvalidArgumentException('Only UDP as transport protocol allowed, yet!');
                }

                return \React\Async\async(function (array $options) {
                    return $this->socket = new UdpSocket($options);
                })($options);


//                $this->socket =
//                    Socket::create($options['host'], [
//                    'transport' => $options['transport'],
//                    'port' => $options['port'],
//                    'buffer_size' => ($options['transport'] === 'udp') ? 65507 : 8192,
//                    'timeout_connect' => $options['timeout_connect'],
//                    'timeout_read' => $options['timeout_read'],
//                    'ssl_validate_cert' => $options['ssl_validate_cert'],
//                    'ssl_allow_self_signed' => $options['ssl_allow_self_signed'],
//                    'ssl_ca_cert' => $options['ssl_ca_cert'],
//                    'ssl_peer_name' => $options['ssl_peer_name'],
//                ]);
            } catch (\Throwable $e) {
                throw new ConnectionException($e->getMessage(), $e->getCode(), $e);
            }
        }
    }

    /**
     * @return SnmpEncoder
     */
    protected function encoder(): SnmpEncoder
    {
        if (!$this->encoder) {
            $this->encoder = new SnmpEncoder();
        }

        return $this->encoder;
    }

}
