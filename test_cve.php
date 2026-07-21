<?php

require __DIR__ . '/lib/ThreatIntel/Services/CVEExtractor.php';

use ThreatIntel\Services\CVEExtractor;

$extractor = new CVEExtractor();

$text = "New security fixes for CVE-2026-12345 and CVE-2026-56789";

$result = $extractor->extract($text);

print_r($result);
