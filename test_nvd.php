<?php

require __DIR__ . '/lib/ThreatIntel/Services/NvdService.php';

use ThreatIntel\Services\NvdService;

$nvd = new NvdService();

$result = $nvd->fetch('CVE-2026-58644');

print_r($result);
