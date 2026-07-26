<?php

namespace ThreatIntel\Services;

use ThreatIntel\Cache\NvdCache;

final class NvdService
{
    private const API =
        'https://services.nvd.nist.gov/rest/json/cves/2.0';

    private NvdCache $cache;

    public function __construct()
    {
        $this->cache = new NvdCache();
    }

    /**
     * @return array<string, mixed>
     */
    public function fetch(string $cve): array
    {
        $cve = strtoupper(trim($cve));

        if (!preg_match('/^CVE-\d{4}-\d{4,}$/', $cve)) {
            return [];
        }

        $cached = $this->cache->get($cve);

        if ($cached !== null) {
            return $cached;
        }

        $url = self::API . '?cveId=' . urlencode($cve);
        $json = @file_get_contents($url);

        if ($json === false) {
            return [];
        }

        $data = json_decode($json, true);

        if (
            !is_array($data)
            || empty($data['vulnerabilities'][0]['cve'])
        ) {
            return [];
        }

        $cveData = $data['vulnerabilities'][0]['cve'];

        $result = [
            'cve' => $cve,
            'source' => 'NVD',
            'description' => '',
            'severity' => null,
            'cvss' => null,
        ];

        foreach ($cveData['descriptions'] ?? [] as $description) {
            if (($description['lang'] ?? null) === 'en') {
                $result['description'] =
                    $description['value'] ?? '';

                break;
            }
        }

        $metrics = $cveData['metrics'] ?? [];
        $cvssData = null;

        if (isset($metrics['cvssMetricV31'][0]['cvssData'])) {
            $cvssData =
                $metrics['cvssMetricV31'][0]['cvssData'];
        } elseif (isset($metrics['cvssMetricV30'][0]['cvssData'])) {
            $cvssData =
                $metrics['cvssMetricV30'][0]['cvssData'];
        }

        if ($cvssData !== null) {
            $result['cvss'] =
                $cvssData['baseScore'] ?? null;

            $result['severity'] =
                $cvssData['baseSeverity'] ?? null;
        }

        $this->cache->set($cve, $result);

        return $result;
    }
}
