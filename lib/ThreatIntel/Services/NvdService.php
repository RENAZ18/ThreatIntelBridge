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

    public function fetch(string $cve): array
    {
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

        if (empty($data['vulnerabilities'][0]['cve'])) {
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


        if (isset($cveData['descriptions'])) {
            foreach ($cveData['descriptions'] as $desc) {
                if ($desc['lang'] === 'en') {
                    $result['description'] = $desc['value'];
                    break;
                }
            }
        }


        $metrics = $cveData['metrics'] ?? [];

        if (isset($metrics['cvssMetricV31'][0])) {

            $cvss =
                $metrics['cvssMetricV31'][0]['cvssData'];

            $result['cvss'] =
                $cvss['baseScore'] ?? null;

            $result['severity'] =
                $cvss['baseSeverity'] ?? null;
        }

        $this->cache->set($cve, $result);
        return $result;
    }
}
