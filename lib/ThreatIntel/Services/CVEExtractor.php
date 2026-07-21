<?php

namespace ThreatIntel\Services;

final class CVEExtractor
{
    /**
     * Extract CVE identifiers from text
     *
     * @return array<int,string>
     */
    public function extract(string $text): array
    {
        preg_match_all(
            '/CVE-\d{4}-\d{4,7}/i',
            $text,
            $matches
        );

        return array_values(
            array_unique(
                array_map(
                    'strtoupper',
                    $matches[0]
                )
            )
        );
    }
}
