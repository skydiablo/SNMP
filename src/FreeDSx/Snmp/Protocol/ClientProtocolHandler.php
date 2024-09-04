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

use FreeDSx\Asn1\Exception\EncoderException;
use FreeDSx\Asn1\Exception\PartialPduException;
use FreeDSx\Snmp\Exception\ConnectionException;
use FreeDSx\Snmp\Exception\InvalidArgumentException;
use FreeDSx\Snmp\Exception\ProtocolException;
use FreeDSx\Snmp\Exception\RediscoveryNeededException;
use FreeDSx\Snmp\Exception\RuntimeException;
use FreeDSx\Snmp\Exception\SecurityModelException;
use FreeDSx\Snmp\Exception\SnmpRequestException;
use FreeDSx\Snmp\Message\EngineId;
use FreeDSx\Snmp\Message\Pdu;
use FreeDSx\Snmp\Message\Response\MessageResponseV3;
use FreeDSx\Snmp\Module\SecurityModel\SecurityModelModuleInterface;
use FreeDSx\Snmp\Protocol\Factory\SecurityModelModuleFactory;
use FreeDSx\Snmp\Message\MessageHeader;
use FreeDSx\Snmp\Message\Request\MessageRequestInterface;
use FreeDSx\Snmp\Message\Request\MessageRequestV1;
use FreeDSx\Snmp\Message\Request\MessageRequestV2;
use FreeDSx\Snmp\Message\Request\MessageRequestV3;
use FreeDSx\Snmp\Message\Response\MessageResponseInterface;
use FreeDSx\Snmp\Message\ScopedPduRequest;
use FreeDSx\Snmp\Protocol\Socket\SocketInterface;
use FreeDSx\Snmp\Request\TrapV1Request;
use FreeDSx\Snmp\Request\TrapV2Request;
use FreeDSx\Snmp\Response\ReportResponse;
use React\EventLoop\Loop;
use React\Promise\Deferred;
use React\Promise\PromiseInterface;
use function is_bool;
use function React\Async\await;
use function React\Promise\resolve;

/**
 * Handles SNMP client protocol logic.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class ClientProtocolHandler
{
    use ProtocolTrait;

    /**
     * @var array
     */
    protected $securityModel = [
        'usm' => 3,
    ];

    /**
     * @param array $options
     * @param SocketInterface|null $socket
     * @param null|SnmpEncoder $encoder
     * @param SecurityModelModuleFactory|null $securityModelFactory
     */
    public function __construct(array $options, ?SocketInterface $socket = null, ?SnmpEncoder $encoder = null, ?SecurityModelModuleFactory $securityModelFactory = null)
    {
        $this->socket = $socket;
        $this->encoder = $encoder;
        $this->options = $options + [
                'transport' => 'udp',
                'use_tls' => false,
                'ssl_validate_cert' => true,
                'ssl_allow_self_signed' => null,
                'ssl_ca_cert' => null,
                'ssl_peer_name' => null,
                'port' => 161,
                'host' => 'localhost',
                'user' => null,
                'community' => 'public',
                'udp_retry' => 5,
                'timeout_connect' => 5,
                'timeout_read' => 10,
                'version' => 2,
                'security_model' => 'usm',
                'engine_id' => null,
                'context_name' => null,
                'use_auth' => false,
                'use_priv' => false,
                'auth_mech' => null,
                'priv_mech' => null,
                'priv_pwd' => null,
                'auth_pwd' => null,
                'id_min' => null,
                'id_max' => null,
            ];
        $this->securityModelFactory = $securityModelFactory ?: new SecurityModelModuleFactory();
    }

    public function __destruct()
    {
//        unset($this->socket);
    }


    /**
     * Handles client protocol logic for an SNMP request to get a potential response.
     *
     * @param Pdu $request
     * @param array $options
     * @return PromiseInterface<?MessageResponseInterface>
     * @throws ConnectionException
     * @throws \Exception
     */
    public function handle(
        Pdu   $request,
        array $options
    ): PromiseInterface
    {
        $deferred = new Deferred();
        $options = \array_merge($this->options, $options);
        $message = $this->getMessageRequest($request, $options);

        if (!\in_array($request->getPduTag(), $this->allowedRequests[$message->getVersion()], true)) {
            $deferred->reject(
                new InvalidArgumentException(sprintf(
                    'The request type "%s" is not allowed in SNMP version %s.',
                    get_class($request),
                    $this->versionMap[$message->getVersion()] ?? 'UNKNOWN'
                ))
            );
        }

        if ($message instanceof MessageRequestV3) {
            $this->sendV3Message($message, $options)->then(function ($response) use ($deferred) {
                $deferred->resolve($response);
            });
        } else {
            $id = $this->generateId();
            $this->setPduId($request, $id);
            $this->sendRequestGetResponse($message)->then(function ($response) use ($deferred, $id) {
                $this->validateResponse($response, $id);
                $deferred->resolve($response);
            }, function ($e) use ($deferred) {
                $deferred->reject($e);
            });
        }
        return $deferred->promise();
    }

    /**
     * Closes the transport connection associated with the client, if any.
     *
     * @return void
     */
    public function close(): void
    {
        if ($this->socket) {
            $this->socket->close();
            $this->socket = null;
        }
    }

    /**
     * @param MessageRequestInterface $message
     * @throws ConnectionException
     * @throws EncoderException
     */
    protected function sendRequestGetResponse(MessageRequestInterface $message)
    {
        $encoder = $this->encoder();
        $rawDataCollector = '';
        return $this->socket()->then(function (SocketInterface $socket) use ($message, $encoder, &$rawDataCollector) {
            $deferred = new Deferred();
            $socket->onData(function ($rawData) use ($encoder, $deferred, &$rawDataCollector) {
                try {
                    $asn1 = $encoder->decode($rawDataCollector ? $rawDataCollector . $rawData : $rawData);
                    $message = \FreeDSx\Snmp\Message\Response\MessageResponse::fromAsn1($asn1);
                    $deferred->resolve($message);
                } catch (PartialPduException $e) {
                    $rawDataCollector .= $rawData;
                } catch (\Throwable $e) {
                    $deferred->reject(
                        new ConnectionException(sprintf('Error for message received from host "%s".', $this->options['host'] ?? 'unknown'), $e->getCode(), $e)
                    );
                }
            })->onError(function ($e) use ($deferred) {
                $deferred->reject($e);
            });

            //give a chance to register all the callbacks
            Loop::futureTick(function () use ($socket, $message, $encoder) {
                $socket->write(
                    $encoder->encode($message->toAsn1())
                );
            });

            # No responses expected from traps...
            if ($message->getRequest() instanceof TrapV1Request || $message->getRequest() instanceof TrapV2Request) {
                return resolve(null);
            }

            return $deferred->promise();

        });
    }

    /**
     * @param MessageRequestV3 $message
     * @param array $options
     * @param bool $forcedDiscovery
     * @return PromiseInterface<?MessageResponseV3>
     * @throws ConnectionException
     * @throws SnmpRequestException
     * @throws EncoderException
     * @throws \FreeDSx\Snmp\Exception\ProtocolException
     * @throws SecurityModelException
     */
    protected function sendV3Message(
        MessageRequestV3 $message,
        array            $options,
        bool             $forcedDiscovery = false
    ): PromiseInterface
    {
        $response = null;
        $header = $message->getMessageHeader();
        $securityModule = $this->securityModelFactory->get($header->getSecurityModel());

        try {
            if ($forcedDiscovery || $securityModule->isDiscoveryRequestNeeded($message, $options)) {
                $response = await($this->performDiscovery($message, $securityModule, $options));
            }

            $id = $this->generateId();
            $this->setPduId($message->getRequest(), $id);
            $message = $securityModule->handleOutgoingMessage($message, $options);
            if (!$message instanceof MessageRequestV3) {
                throw new ProtocolException(sprintf(
                    'Expected an SNMPv3 message request. Got v%d',
                    $message->getVersion()
                ));
            }
            return $this->sendRequestGetResponse($message)->then(function ($response) use ($securityModule, $options, $id) {
                if ($response instanceof MessageResponseV3) {
                    $response = $securityModule->handleIncomingMessage($response, $options);
                }
                if (!$response instanceof MessageResponseV3) {
                    throw new ProtocolException(sprintf(
                        'Expected a SNMPv3 response, but got: v%d',
                        $response instanceof MessageResponseInterface ? $response->getVersion() : 0
                    ));
                }
                $this->validateResponse($response, $id);
                return $response;
            });

        } catch (RediscoveryNeededException $e) {
            if (!$forcedDiscovery) {
                return $this->sendV3Message($message, $options, true);
            }
            throw new SnmpRequestException($response, $e->getMessage(), $e);
        } catch (SecurityModelException $e) {
            throw new SnmpRequestException($response, $e->getMessage(), $e);
        }
    }

    /**
     * @param MessageRequestV3 $message
     * @param SecurityModelModuleInterface $securityModule
     * @param array $options
     * @throws ConnectionException
     * @throws EncoderException
     * @throws SnmpRequestException
     */
    protected function performDiscovery(
        MessageRequestV3             $message,
        SecurityModelModuleInterface $securityModule,
        array                        $options
    )
    {
        $discovery = $securityModule->getDiscoveryRequest($message, $options);
        $id = $this->generateId();
        $this->setPduId($discovery->getRequest(), $id);
        return $this->sendRequestGetResponse($discovery)->then(function($response) use ($options, $message, $id, $discovery, $securityModule) {
            if (!$response instanceof MessageResponseV3) {
                throw new ProtocolException(sprintf(
                    'Expected an SNMPv3 response. Received v%d.',
                    $response instanceof MessageResponseInterface ? $response->getVersion() : 0
                ));
            }
            $this->validateResponse($response, $id, false);
            $securityModule->handleDiscoveryResponse($message, $response, $options);
            return $response;
        });

    }

    /**
     * @param Pdu $request
     * @param array $options
     * @return MessageRequestInterface
     * @throws \Exception
     */
    protected function getMessageRequest(Pdu $request, array $options): MessageRequestInterface
    {
        if ($options['version'] === 1) {
            return new MessageRequestV1($options['community'], $request);
        } elseif ($options['version'] === 2) {
            return new MessageRequestV2($options['community'], $request);
        } elseif ($options['version'] === 3) {
            $engineId = ($options['engine_id'] instanceof EngineId) ? $options['engine_id'] : null;
            return new MessageRequestV3(
                $this->generateMessageHeader($request, $options),
                new ScopedPduRequest($request, $engineId, (string)$options['context_name'])
            );
        } else {
            throw new RuntimeException(sprintf('SNMP version %s is not supported', $options['version']));
        }
    }

    /**
     * Needed to set the ID in the PDU. Unfortunately the protocol designers put the ID for the overall message inside
     * of the PDU (essentially the request / response objects). This made it awkward to work with when separating the
     * logic of the ID generation /message creation. Maybe a better way to handle this in general?
     */
    protected function setPduId(Pdu $request, int $id): void
    {
        # The Trap v1 PDU has no request ID associated with it.
        if ($request instanceof TrapV1Request) {
            return;
        }
        $requestObject = new \ReflectionObject($request);
        $idProperty = $requestObject->getProperty('id');
        $idProperty->setAccessible(true);
        $idProperty->setValue($request, $id);
    }

    /**
     * @param Pdu $request
     * @param array $options
     * @return MessageHeader
     * @throws \Exception
     */
    protected function generateMessageHeader(
        Pdu   $request,
        array $options
    ): MessageHeader
    {
        $header = new MessageHeader($this->generateId(0));

        $useAuth = $options['use_auth'];
        $usePriv = $options['use_priv'];
        if (!is_bool($useAuth) || !is_bool($usePriv)) {
            throw new InvalidArgumentException('Options use_auth and use_priv must have boolean value.');
        }

        if ($useAuth || $usePriv) {
            if (!isset($this->securityModel[$options['security_model']])) {
                throw new InvalidArgumentException(sprintf(
                    'The security model %s is not recognized.',
                    $options['security_model']
                ));
            }
            $header->setSecurityModel($this->securityModel[$options['security_model']]);
        }
        if ($useAuth) {
            $header->addFlag(MessageHeader::FLAG_AUTH);
        }
        if ($usePriv) {
            $header->addFlag(MessageHeader::FLAG_PRIV);
        }
        # Unconfirmed PDUs do not have the reportable flag set
        if (!$request instanceof TrapV2Request) {
            $header->addFlag(MessageHeader::FLAG_REPORTABLE);
        }

        return $header;
    }

    /**
     * @param null|MessageResponseInterface $message
     * @param int $expectedId
     * @param bool $throwOnReport
     * @throws SnmpRequestException
     */
    protected function validateResponse(?MessageResponseInterface $message, int $expectedId, bool $throwOnReport = true): void
    {
        if ($message === null) {
            return;
        }
        $response = $message->getResponse();
        if (!\in_array($response->getPduTag(), $this->allowedResponses[$message->getVersion()], true)) {
            throw new SnmpRequestException($message, sprintf(
                'The PDU type received (%s) is not allowed in SNMP version %s.',
                get_class($response),
                $this->versionMap[$message->getVersion()]
            ));
        }
        if ($throwOnReport && $response instanceof ReportResponse) {
            $oids = [];
            foreach ($response->getOids() as $oid) {
                $oids[] = $oid->getOid();
            }
            throw new SnmpRequestException($message, sprintf(
                'Received a report PDU with the OID(s): %s',
                implode(', ', $oids)
            ));
        }
        if (($response->getId() !== $expectedId) && ($response->getId() != 0)) {
            throw new SnmpRequestException($message, sprintf(
                'Unexpected message ID received. Expected %s but got %s.',
                $expectedId,
                $response->getId()
            ));
        }
        if ($response->getErrorStatus() !== 0) {
            throw new SnmpRequestException($message);
        }
    }
}
