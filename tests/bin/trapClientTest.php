<?php

declare(strict_types=1);

use FreeDSx\Snmp\SnmpClient;

require __DIR__.'/../../vendor/autoload.php';

$client = new SnmpClient([
    'port' => 10162,
]);

$client->sendTrap(
    123,
    '1.2.3.4.5',
);

\React\EventLoop\Loop::addPeriodicTimer(
    1,
    fn() => $client->sendTrap(123, '1.2.3.4.5'),
);

\React\EventLoop\Loop::addTimer(3, fn() => \React\EventLoop\Loop::stop());