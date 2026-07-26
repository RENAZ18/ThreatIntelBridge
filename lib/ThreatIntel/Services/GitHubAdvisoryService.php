<?php

namespace ThreatIntel\Services;

final class GitHubAdvisoryService
{
    private const API = 'https://api.github.com/advisories';

    /**
     * Fetch recent GitHub Security Advisories.
     *
     * @return array<int, array<string, mixed>>
     */
    public function fetch(int $limit = 10): array
    {
        $limit = max(1, min($limit, 100));

        $url = self::API
            . '?type=reviewed'
            . '&per_page=' . $limit
            . '&sort=published'
            . '&direction=desc';

        $headers = [
            'Accept: application/vnd.github+json',
            'X-GitHub-Api-Version: 2022-11-28',
            'User-Agent: ThreatIntelBridge',
        ];

        $token = getenv('GITHUB_TOKEN');

        if (!empty($token)) {
            $headers[] = 'Authorization: Bearer ' . $token;
        }

        $context = stream_context_create([
            'http' => [
                'method' => 'GET',
                'header' => implode("\r\n", $headers),
                'timeout' => 10,
                'ignore_errors' => true,
            ],
        ]);

        $json = @file_get_contents($url, false, $context);

        $statusLine = $http_response_header[0] ?? 'Unknown status';

        if ($json === false) {
            return [];
        }

        if (!str_contains($statusLine, '200')) {
            return [];
        }

        $data = json_decode($json, true);

        if (!is_array($data)) {
            return [];
        }

        $items = [];

        foreach ($data as $advisory) {
            if (!is_array($advisory)) {
                continue;
            }

            $cve = $advisory['cve_id'] ?? null;

            /*
             * The Correlator currently groups items by CVE,
             * so advisories without a CVE are skipped.
             */
            if (empty($cve)) {
                continue;
            }

            $items[] = [
                'cve' => strtoupper($cve),
                'title' => $advisory['summary'] ?? 'Unknown GitHub advisory',
                'source' => 'GitHub',
                'description' => $advisory['description'] ?? '',
                'severity' => isset($advisory['severity'])
                    ? strtoupper($advisory['severity'])
                    : null,
                'cvss' => $this->extractCvss($advisory),
                'uri' => $advisory['html_url']
                    ?? 'https://github.com/advisories',
                'dateAdded' => $advisory['published_at'] ?? null,
                'ghsaId' => $advisory['ghsa_id'] ?? null,
            ];
        }

        return $items;
    }

    /**
     * Extract the best available CVSS score.
     */
    private function extractCvss(array $advisory): ?float
    {
        $cvssV4 = $advisory['cvss_severities']['cvss_v4']['score'] ?? null;

        if (is_numeric($cvssV4) && (float) $cvssV4 > 0) {
            return (float) $cvssV4;
        }

        $cvssV3 = $advisory['cvss_severities']['cvss_v3']['score'] ?? null;

        if (is_numeric($cvssV3) && (float) $cvssV3 > 0) {
            return (float) $cvssV3;
        }

        $legacyScore = $advisory['cvss']['score'] ?? null;

        if (is_numeric($legacyScore) && (float) $legacyScore > 0) {
            return (float) $legacyScore;
        }

        return null;
    }
}
