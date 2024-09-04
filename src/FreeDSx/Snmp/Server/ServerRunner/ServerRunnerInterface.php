<?php
/**
 * This file is part of the FreeDSx SNMP package.
 *
 * (c) Chad Sikorra <Chad.Sikorra@gmail.com>
 *
 * For the full copyright and license information, please view the LICENSE
 * file that was distributed with this source code.
 */

namespace FreeDSx\Snmp\Server\ServerRunner;

use FreeDSx\Snmp\Protocol\Socket\ServerSocketInterface;

/**
 * Runs the server to support various transports / handling logic, etc.
 *
 * @author Chad Sikorra <Chad.Sikorra@gmail.com>
 */
interface ServerRunnerInterface
{
    /**
     * Runs the socket server to accept incoming client connections and dispatch them where needed.
     *
     * @param ServerSocketInterface $server
     */
    public function run(ServerSocketInterface $server) : void;
}
