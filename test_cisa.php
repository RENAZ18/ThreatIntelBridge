<?php

require __DIR__ . '/lib/ThreatIntel/Services/CisaService.php';

use ThreatIntel\Services\CisaService;

$service = new CisaService();

$data = $service->fetch();

echo "Total: " . count($data) . PHP_EOL;

print_r(array_slice($data, 0, 3));
