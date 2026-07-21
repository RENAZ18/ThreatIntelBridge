<?php

declare(strict_types=1);

require_once __DIR__ . '/../lib/ThreatIntel/Cache/NvdCache.php';
require_once __DIR__ . '/../lib/ThreatIntel/Services/CisaService.php';
require_once __DIR__ . '/../lib/ThreatIntel/Services/NvdService.php';
require_once __DIR__ . '/../lib/ThreatIntel/Services/Correlator.php';
require_once __DIR__ . '/../lib/ThreatIntel/Models/ThreatEvent.php';

class ThreatIntelBridge extends BridgeAbstract
{
    const NAME = 'Threat Intelligence Aggregator';
    const URI = 'https://www.cisa.gov';
    const DESCRIPTION = 'Aggregates security advisories and correlates CVEs';
    const MAINTAINER = 'renaz';
    const CACHE_TIMEOUT = 3600;

    public function collectData()
    {
        $cisa = new \ThreatIntel\Services\CisaService();
        $cisaItems = $cisa->fetch();

        $nvd = new \ThreatIntel\Services\NvdService();

        $allItems = [];

        foreach (array_slice($cisaItems, 0, 10) as $item) {

            $allItems[] = $item;

            if (!empty($item['cve'])) {

                $nvdData = $nvd->fetch($item['cve']);

                if (!empty($nvdData)) {
                    $allItems[] = array_merge($item, $nvdData);
                }
            }
        }

        $correlator = new \ThreatIntel\Services\Correlator();
        $events = $correlator->correlate($allItems);

        foreach ($events as $event) {

            $content = [];

            $content[] = 'Sources: ' . implode(', ', $event->sources);

            if ($event->severity !== null) {
                $content[] = 'Severity: ' . $event->severity;
            }

            if ($event->cvss !== null) {
                $content[] = 'CVSS: ' . $event->cvss;
            }

            if (!empty($event->description)) {
                $content[] = 'Description: ' . $event->description;
            }

            $this->items[] = [
                'title' => $event->cveId . ' - ' . $event->title,
                'content' => implode('<br>', $content),
                'uri' => $event->items[0]['uri'] ?? self::URI,
                'timestamp' => strtotime($event->items[0]['dateAdded'] ?? 'now'),
                'uid' => $event->cveId,
            ];
        }
    }
}
