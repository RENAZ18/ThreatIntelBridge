<?php

require __DIR__ . '/lib/ThreatIntel/Models/ThreatEvent.php';
require __DIR__ . '/lib/ThreatIntel/Services/Correlator.php';

use ThreatIntel\Services\Correlator;


$items = [

    [
        'cve' => 'CVE-2026-12345',
        'title' => 'Microsoft vulnerability',
        'source' => 'CISA',
        'uri' => 'https://cisa.example'
    ],

    [
        'cve' => 'CVE-2026-12345',
        'title' => 'GitHub advisory',
        'source' => 'GitHub',
        'uri' => 'https://github.example'
    ],

    [
        'cve' => 'CVE-2026-12345',
        'title' => 'Microsoft vulnerability',
        'source' => 'NVD',
        'severity' => 'CRITICAL',
        'cvss' => 9.8,
        'description' => 'Deserialization of untrusted data vulnerability',
        'uri' => 'https://nvd.nist.gov'
    ]

];


$correlator = new Correlator();

$result = $correlator->correlate($items);

print_r($result);
