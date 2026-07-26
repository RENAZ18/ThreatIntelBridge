<?php

declare(strict_types=1);

namespace ThreatIntel\Database;

use PDO;
use ThreatIntel\Models\ThreatEvent;

class ThreatEventRepository
{
    public function __construct(
        private PDO $connection
    ) {
    }

    public function save(ThreatEvent $event): void
    {
        $now = date('c');

        $firstSeen = $this->extractPublishedDate($event) ?? $now;
        $lastSeen = $firstSeen;

        $statement = $this->connection->prepare(
            "
            INSERT INTO threat_events (
                cve_id,
                title,
                description,
                severity,
                cvss,
                first_seen,
                last_seen,
                created_at,
                updated_at
            )
            VALUES (
                :cve_id,
                :title,
                :description,
                :severity,
                :cvss,
                :first_seen,
                :last_seen,
                :created_at,
                :updated_at
            )
            ON CONFLICT(cve_id) DO UPDATE SET
                title = excluded.title,
                description = CASE
                    WHEN excluded.description IS NOT NULL
                         AND excluded.description != ''
                    THEN excluded.description
                    ELSE threat_events.description
                END,
                severity = COALESCE(
                    excluded.severity,
                    threat_events.severity
                ),
                cvss = COALESCE(
                    excluded.cvss,
                    threat_events.cvss
                ),
                last_seen = excluded.last_seen,
                updated_at = excluded.updated_at

             "
        );

        $statement->execute([
            ':cve_id' => $event->cveId,
            ':title' => $event->title,
            ':description' => $event->description,
            ':severity' => $event->severity,
            ':cvss' => $event->cvss,
            ':first_seen' => $firstSeen,
            ':last_seen' => $lastSeen,
            ':created_at' => $now,
            ':updated_at' => $now,
        ]);

        $threatEventId = $this->findIdByCve($event->cveId);

        if ($threatEventId === null) {
            return;
        }

        $this->saveSources($threatEventId, $event, $now);
    }

    private function findIdByCve(string $cveId): ?int
    {
        $statement = $this->connection->prepare(
            '
            SELECT id
            FROM threat_events
            WHERE cve_id = :cve_id
            '
        );

        $statement->execute([
            ':cve_id' => $cveId,
        ]);

        $id = $statement->fetchColumn();

        return $id === false ? null : (int) $id;
    }

    private function saveSources(
        int $threatEventId,
        ThreatEvent $event,
        string $now
    ): void {
        foreach ($event->items as $item) {
            $source = $item['source'] ?? null;

            if (empty($source)) {
                continue;
            }

            $statement = $this->connection->prepare(
                '
                INSERT INTO event_sources (
                    threat_event_id,
                    source,
                    source_url,
                    published_at,
                    created_at
                )
                VALUES (
                    :threat_event_id,
                    :source,
                    :source_url,
                    :published_at,
                    :created_at
                )
                ON CONFLICT(threat_event_id, source) DO UPDATE SET
                    source_url = excluded.source_url,
                    published_at = excluded.published_at
                '
            );

            $statement->execute([
                ':threat_event_id' => $threatEventId,
                ':source' => $source,
                ':source_url' => $this->resolveSourceUrl(
                    $source,
                    $item,
                    $event->cveId
                ),
                ':published_at' => $item['dateAdded'] ?? null,
                ':created_at' => $now,
            ]);
        }
    }

    private function resolveSourceUrl(
        string $source,
        array $item,
        string $cveId
    ): ?string {
        $normalizedSource = strtoupper(trim($source));
    
        if ($normalizedSource === 'NVD') {
            return 'https://nvd.nist.gov/vuln/detail/'
                . rawurlencode($cveId);
        }
    
        return $item['uri']
            ?? $item['url']
            ?? null;
    }

    private function extractPublishedDate(ThreatEvent $event): ?string
    {
        foreach ($event->items as $item) {
            if (!empty($item['dateAdded'])) {
                return $item['dateAdded'];
            }
        }

        return null;
    }
}
