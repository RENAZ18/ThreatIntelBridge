<?php

namespace ThreatIntel\Services;

final class CisaService
{
    private const KEV_URL =
        'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json';

    /**
     * @return array<int, array<string,mixed>>
     */
    public function fetch(): array
    {
        $json = @file_get_contents(self::KEV_URL);

        if ($json === false) {
            return [];
        }

        $data = json_decode($json, true);

        if (!isset($data['vulnerabilities'])) {
            return [];
        }

        $items = [];

        foreach ($data['vulnerabilities'] as $vuln) {

            $items[] = [
                'cve' => strtoupper($vuln['cveID']),
                'title' => $vuln['vulnerabilityName'],
                'source' => 'CISA',
                'vendor' => $vuln['vendorProject'],
                'product' => $vuln['product'],
                'dateAdded' => $vuln['dateAdded'],
                'uri' => 'https://www.cisa.gov/known-exploited-vulnerabilities-catalog',
            ];
        }

        return $items;
    }
}
