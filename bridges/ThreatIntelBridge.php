<?php

declare(strict_types=1);

require_once __DIR__ . '/../lib/ThreatIntel/Cache/NvdCache.php';

require_once __DIR__ . '/../lib/ThreatIntel/Database/Database.php';
require_once __DIR__ . '/../lib/ThreatIntel/Database/Schema.php';
require_once __DIR__ . '/../lib/ThreatIntel/Database/ThreatEventRepository.php';

require_once __DIR__ . '/../lib/ThreatIntel/Models/ThreatEvent.php';

require_once __DIR__ . '/../lib/ThreatIntel/Services/CisaService.php';
require_once __DIR__ . '/../lib/ThreatIntel/Services/NvdService.php';
require_once __DIR__ . '/../lib/ThreatIntel/Services/GitHubAdvisoryService.php';
require_once __DIR__ . '/../lib/ThreatIntel/Services/Correlator.php';

class ThreatIntelBridge extends BridgeAbstract
{
    const NAME = 'Threat Intelligence Aggregator';
    const URI = 'https://www.cisa.gov';
    const DESCRIPTION = 'Aggregates security advisories and correlates CVEs';
    const MAINTAINER = 'renaz';
    const CACHE_TIMEOUT = 3600;

    public function collectData()
    {
        $database = new \ThreatIntel\Database\Database();
        $connection = $database->getConnection();

        \ThreatIntel\Database\Schema::create($connection);

        $cisa = new \ThreatIntel\Services\CisaService();
        $cisaItems = $cisa->fetch();

        $nvd = new \ThreatIntel\Services\NvdService();

        $github = new \ThreatIntel\Services\GitHubAdvisoryService();
        $githubItems = $github->fetch();

        $allItems = $githubItems;

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

        $repository = new \ThreatIntel\Database\ThreatEventRepository($connection);

        foreach ($events as $event) {
            $repository->save($event);
        }

        $severityOrder = [
            'CRITICAL' => 4,
            'HIGH' => 3,
            'MEDIUM' => 2,
            'LOW' => 1,
        ];

        usort($events, function ($a, $b) use ($severityOrder) {
            $aSeverity = strtoupper($a->severity ?? '');
            $bSeverity = strtoupper($b->severity ?? '');

            $aPriority = $severityOrder[$aSeverity] ?? 0;
            $bPriority = $severityOrder[$bSeverity] ?? 0;

            if ($aPriority === $bPriority) {
                return ($b->cvss ?? 0) <=> ($a->cvss ?? 0);
            }

            return $bPriority <=> $aPriority;
        });

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
                $description = strip_tags($event->description);

                // Remove basic Markdown characters.
                $description = preg_replace('/[`#*_>-]+/', ' ', $description);
                $description = preg_replace('/\s+/', ' ', $description);
                $description = trim($description);

                $maxLength = 300;

                if (strlen($description) > $maxLength) {
                    $description = substr($description, 0, $maxLength) . '...';
                }

                $content[] = 'Description: ' . $description;
            }

            $this->items[] = [
                'title' => $event->cveId . ' - ' . $event->title,
                'content' => implode('<br>', $content),
                'uri' => $event->items[0]['uri'] ?? self::URI,
                'timestamp' => strtotime(
                    $event->items[0]['dateAdded'] ?? 'now'
                ),
                'uid' => $event->cveId,
            ];
        }
    }
}
