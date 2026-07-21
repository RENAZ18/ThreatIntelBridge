<?php

require __DIR__ . '/lib/ThreatIntel/Models/ThreatEvent.php';

use ThreatIntel\Models\ThreatEvent;

$event = new ThreatEvent(
    'CVE-2026-12345',
    'Test vulnerability'
);

$event->addSource('CISA');
$event->addSource('GitHub');

print_r($event);
