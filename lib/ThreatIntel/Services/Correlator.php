<?php

namespace ThreatIntel\Services;

use ThreatIntel\Models\ThreatEvent;

final class Correlator
{
    /**
     * @param array<int,array> $items
     * @return array<string,ThreatEvent>
     */
    public function correlate(array $items): array
    {
        $events = [];

        foreach ($items as $item) {

            if (!isset($item['cve'])) {
                continue;
            }

            $cve = strtoupper($item['cve']);

            if (!isset($events[$cve])) {
                $events[$cve] = new ThreatEvent(
                    $cve,
                    $item['title'] ?? 'Unknown threat'
                );
            }

            if (isset($item['source'])) {
                $events[$cve]->addSource(
                    $item['source']
                );
            }

            // NVD enrichment
            if (isset($item['severity'])) {
                $events[$cve]->severity = $item['severity'];
            }

            if (isset($item['cvss'])) {
                $events[$cve]->cvss = $item['cvss'];
            }

            if (isset($item['description'])) {
                $events[$cve]->description = $item['description'];
            }

            $events[$cve]->items[] = $item;
        }

        return $events;
    }
}
