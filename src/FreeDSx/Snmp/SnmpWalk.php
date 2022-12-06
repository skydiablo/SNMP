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

use FreeDSx\Snmp\Exception\EndOfWalkException;
use FreeDSx\Snmp\Exception\RuntimeException;
use React\Promise\Deferred;
use React\Promise\PromiseInterface;
use function count;
use function React\Promise\resolve;

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
     * @var Oid|null
     */
    protected $current;

    /**
     * @var Oid[]
     */
    protected $next = [];

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
     * @param SnmpClient $client
     * @param null|string $startAt
     * @param null|string $endAt
     * @param bool $subtreeOnly
     */
    public function __construct(SnmpClient $client, ?string $startAt = null, ?string $endAt = null, bool $subtreeOnly = true)
    {
        $this->client = $client;
        $this->startAt = $startAt ?? '1.3.6.1.2.1';
        $this->endAt = $endAt;
        $this->subtreeOnly = $subtreeOnly;
    }

    public function walk(callable $callback, ?Oid $referenceOid = null): void
    {
        $this->getNextOid($referenceOid)->then(function (array $oids) use ($callback) {
            if ($oids) {
                $currentOid = null;
                foreach ($oids as $oid) {
                    $this->count++;
                    $currentOid = $oid;
                    $cancel = $this->isComplete($oid) || !call_user_func($callback, $oid, $this);
                    if ($cancel) {
                        return;
                    }
                }
                $this->walk($callback, $currentOid);
            } else {
                throw new EndOfWalkException();
            }
        })->otherwise(function ($e) {
            var_dump($e);
            throw $e;
        });
    }

    /**
     * @return bool
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     * @throws EndOfWalkException
     */
    protected function isComplete(Oid $oid): bool
    {
        if ($oid->isEndOfMibView()) {
            return true;
        }
        if ($oid->getOid() === $this->endAt) {
            return true;
        }
        if ($this->subtreeOnly) {
            return $this->isEndOfSubtree($oid);
        }

        return false;
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
     * @return bool
     * @throws Exception\ConnectionException
     * @throws Exception\SnmpRequestException
     * @throws EndOfWalkException
     */
    protected function isEndOfSubtree(Oid $oid): bool
    {
        return (\substr($oid->getOid(), 0, \strlen($this->startAt)) !== $this->startAt);
    }

}
