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

use React\Promise\Deferred;
use React\Promise\PromiseInterface;

/**
 * Provides a simple API to perform an SNMP walk.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
class SnmpWalk
{
    /**
     * @var SnmpClient
     */
    protected $client;

    /**
     * @var string
     */
    protected $startAt;

    /**
     * @var null|string
     */
    protected $endAt;

    /**
     * @var int
     */
    protected $count = 0;

    /**
     * @var bool
     */
    protected $subtreeOnly;

    /**
     * @var null|bool
     */
    protected $useGetBulk;

    /**
     * @var int
     */
    protected $maxRepetitions = 100;

    /**
     * Is this walk in run mode
     * @var bool
     */
    protected bool $run = true;

    /**
     * @param SnmpClient $client
     * @param null|string $startAt
     * @param null|string $endAt
     * @param bool $subtreeOnly
     */
    public function __construct(SnmpClient $client, ?string $startAt = null, ?string $endAt = null, bool $subtreeOnly = true)
    {
        $this->client = $client;
        $this->startAt = $startAt ?: '1.3.6.1.2.1';
        $this->endAt = $endAt;
        $this->subtreeOnly = $subtreeOnly;
    }

    /**
     * @return SnmpClient
     */
    public function getClient(): SnmpClient
    {
        return $this->client;
    }

    /**
     * @return string
     */
    public function getStartAt(): string
    {
        return $this->startAt;
    }

    /**
     * @return string|null
     */
    public function getEndAt(): ?string
    {
        return $this->endAt;
    }

    public function stop(): void
    {
        $this->run = false;
        $this->client->close();
    }

    /**
     * @param callable $callback
     * @param Oid|null $referenceOid
     * @return PromiseInterface
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     */
    public function walk(callable $callback, ?Oid $referenceOid = null): PromiseInterface
    {
        $deferred = new Deferred();
        $this->run = true;
        $this->getNextOid($referenceOid)->then(function (array $oids) use ($callback, $deferred) {
            if ($oids) {
                $currentOid = null;
                foreach ($oids as $oid) {
                    $this->count++;
                    $currentOid = $oid;
                    $cancel = $this->isComplete($oid)
                        || !call_user_func($callback, $oid, $this);
                    if ($cancel) {
                        $deferred->resolve($this);
                        return;
                    }
                }
                $this->walk($callback, $currentOid)->then(fn(self $that) => $deferred->resolve($that));
            } else {
                $deferred->resolve($this);
            }
        })->otherwise(function ($e) use ($deferred) {
            $deferred->reject($e);
        });
        return $deferred->promise();
    }

    /**
     * @param Oid $oid
     * @return bool
     */
    protected function isComplete(Oid $oid): bool
    {
        return !$this->run
            || $oid->isEndOfMibView()
            || ($oid->getOid() === $this->endAt)
            || ($this->subtreeOnly && $this->isEndOfSubtree($oid));
    }

    /**
     * Get the number of OIDs walked.
     *
     * @return int
     */
    public function count(): int
    {
        return $this->count;
    }

    /**
     * @param bool $subtreeOnly
     * @return $this
     */
    public function subtreeOnly(bool $subtreeOnly = true)
    {
        $this->subtreeOnly = $subtreeOnly;

        return $this;
    }

    /**
     * Set the walk to begin at a specific OID.
     *
     * @param string $oid
     * @return $this
     */
    public function startAt(string $oid)
    {
        $this->startAt = $oid;

        return $this;
    }

    /**
     * Set the walk to end at a specific OID.
     *
     * @param string $oid
     * @return $this
     */
    public function endAt(string $oid)
    {
        $this->endAt = $oid;

        return $this;
    }

    /**
     * Explicitly set whether or not to use the GetBulk method for OID retrieval in a SNMPv2 / SNMPv3 context. If the
     * SNMP version is set to v1 then it will only use GetNext regardless.
     *
     * By default GetBulk is used if the SNMP version supports it.
     *
     * @param bool $useGetBulk
     * @return $this
     */
    public function useGetBulk(bool $useGetBulk)
    {
        $this->useGetBulk = $useGetBulk;

        return $this;
    }

    /**
     * Use a specific number of max repetitions (applicable if using GetBulk requests). This is the number of OIDs that
     * a GetBulk will request to return at once. Depending on the remote host, this might need to be toggled.
     *
     * @param int $maxRepetitions
     * @return $this
     */
    public function maxRepetitions(int $maxRepetitions)
    {
        $this->maxRepetitions = $maxRepetitions;

        return $this;
    }

    /**
     * @return PromiseInterface<Oid[]>
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     */
    protected function getNextOid(?Oid $reference): PromiseInterface
    {
        $currentOid = $reference ? $reference->getOid() : $this->startAt;

        if (($this->useGetBulk === null || $this->useGetBulk) && $this->client->getOptions()['version'] >= 2) {
            return $this->client->getBulk($this->maxRepetitions, 0, $currentOid)->then(function (OidList $oidList) {
                return $oidList->toArray();
            });
        } else {
            return $this->client->getNext($currentOid)->then(function (OidList $oidList) {
                return $oidList->toArray();
            });
        }
    }

    /**
     * @param Oid $oid
     * @return bool
     */
    protected function isEndOfSubtree(Oid $oid): bool
    {
        return !str_starts_with($oid->getOid(), $this->startAt);
    }

}
