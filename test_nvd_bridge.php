<?php

require_once 'lib/ThreatIntel/Services/NvdService.php';

$nvd = new \ThreatIntel\Services\NvdService();

print_r(
    $nvd->fetch('CVE-2020-16009')
);
