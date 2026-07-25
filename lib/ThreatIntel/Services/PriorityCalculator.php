<?php

declare(strict_types=1);

namespace ThreatIntel\Services;

use DateTimeImmutable;
use Throwable;

class PriorityCalculator
{
    /**
     * @param array<int, string>|string $sources
     *
     * @return array{
     *     score: int,
     *     priority: string
     * }
     */
    public function calculate(
        array|string $sources,
        ?string $severity,
        ?float $cvss,
        ?string $publishedDate
    ): array {
        $score = 0;

        $normalizedSources = $this->normalizeSources($sources);

        /*
         * Source score:
         * CISA   = 3
         * NVD    = 1
         * GitHub = 1
         */
        if (in_array('CISA', $normalizedSources, true)) {
            $score += 3;
        }

        if (in_array('NVD', $normalizedSources, true)) {
            $score += 1;
        }

        if (in_array('GITHUB', $normalizedSources, true)) {
            $score += 1;
        }

        /*
         * Severity score:
         * Critical = 3
         * High     = 2
         * Medium   = 1
         * Low      = 0
         */
        $score += match (strtoupper(trim($severity ?? ''))) {
            'CRITICAL' => 3,
            'HIGH' => 2,
            'MEDIUM', 'MODERATE' => 1,
            default => 0,
        };

        /*
         * CVSS score:
         * 9.0–10.0 = 2
         * 7.0–8.9  = 1
         */
        if ($cvss !== null) {
            if ($cvss >= 9.0) {
                $score += 2;
            } elseif ($cvss >= 7.0) {
                $score += 1;
            }
        }

        /*
         * Recently published:
         * Within the last 7 days = 1
         */
        if ($this->isRecent($publishedDate)) {
            $score += 1;
        }

        return [
            'score' => $score,
            'priority' => $this->resolvePriority($score),
        ];
    }

    /**
     * @param array<int, string>|string $sources
     *
     * @return array<int, string>
     */
    private function normalizeSources(array|string $sources): array
    {
        if (is_string($sources)) {
            $sources = preg_split('/\s*,\s*/', $sources) ?: [];
        }

        return array_values(
            array_unique(
                array_filter(
                    array_map(
                        static fn (string $source): string =>
                            strtoupper(trim($source)),
                        $sources
                    )
                )
            )
        );
    }

    private function isRecent(?string $publishedDate): bool
    {
        if ($publishedDate === null || trim($publishedDate) === '') {
            return false;
        }

        try {
            $published = new DateTimeImmutable($publishedDate);
            $sevenDaysAgo = new DateTimeImmutable('-7 days');

            return $published >= $sevenDaysAgo;
        } catch (Throwable) {
            return false;
        }
    }

    private function resolvePriority(int $score): string
    {
        return match (true) {
            $score >= 8 => 'Urgent',
            $score >= 5 => 'High',
            $score >= 3 => 'Medium',
            default => 'Low',
        };
    }
}
