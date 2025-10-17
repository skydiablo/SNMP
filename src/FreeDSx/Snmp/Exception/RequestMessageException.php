<?php

declare(strict_types=1);

namespace FreeDSx\Snmp\Exception;

use FreeDSx\Snmp\Message\Request\MessageRequestInterface;

class RequestMessageException extends RuntimeException
{

    protected ?MessageRequestInterface $request = null;

    public function getRequest(): ?MessageRequestInterface
    {
        return $this->request;
    }

    public function setRequest(?MessageRequestInterface $request): self
    {
        $this->request = $request;

        return $this;
    }


}