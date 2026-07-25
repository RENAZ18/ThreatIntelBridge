<?php

declare(strict_types=1);

require_once __DIR__ . '/lib/ThreatIntel/Database/Database.php';
require_once __DIR__ . '/lib/ThreatIntel/Database/ThreatEventQueryRepository.php';
require_once __DIR__ . '/lib/ThreatIntel/Services/PriorityCalculator.php';

use ThreatIntel\Database\Database;
use ThreatIntel\Database\ThreatEventQueryRepository;

$database = new Database();
$priorityCalculator = new \ThreatIntel\Services\PriorityCalculator();

$repository = new ThreatEventQueryRepository(
    $database->getConnection()
);

$id = filter_input(INPUT_GET, 'id', FILTER_VALIDATE_INT);

if ($id === false || $id === null) {
    http_response_code(400);
    exit('Invalid threat event ID.');
}

$event = $repository->findById($id);

if ($event === null) {
    http_response_code(404);
    exit('Threat event not found.');
}

$priority = $priorityCalculator->calculate(
    $event['sources'] ?? [],
    $event['severity'] ?? null,
    $event['cvss'] !== null ? (float) $event['cvss'] : null,
    $event['first_seen'] ?? null
);

function cleanFullDescription(
    ?string $description,
    int $maxLength = 900
): string {
    if ($description === null || trim($description) === '') {
        return '';
    }

    $description = html_entity_decode(
        $description,
        ENT_QUOTES | ENT_HTML5,
        'UTF-8'
    );

    // Remove fenced code blocks.
    $description = preg_replace(
        '/```[\s\S]*?```/',
        ' ',
        $description
    ) ?? $description;

    // Convert Markdown links: [text](url) -> text.
    $description = preg_replace(
        '/\[([^\]]+)\]\([^)]+\)/',
        '$1',
        $description
    ) ?? $description;

    // Stop before detailed advisory sections.
    $sections = [
        'Impact',
        'Patches',
        'Workarounds',
        'Mitigation',
        'Mitigations',
        'References',
        'Credits',
        'Acknowledgements',
        'Additional Information',
    ];

    $sectionPattern = implode(
        '|',
        array_map('preg_quote', $sections)
    );

    $originalDescription = $description;
    
    $parts = preg_split(
        '/^\s*#{0,6}\s*(?:' . $sectionPattern . ')\s*:?\s*$/mi',
        $description,
        2
    );
    
    if (
        isset($parts[0])
        && trim($parts[0]) !== ''
    ) {
        $description = $parts[0];
    } else {
        $description = $originalDescription;
    }
    
    // Remove Markdown headings.
    $description = preg_replace(
        '/^\s{0,3}#{1,6}\s*/m',
        '',
        $description
    ) ?? $description;

    // Remove Markdown notes and blockquotes.
    $description = preg_replace(
        '/^\s*>\s*(?:\[![A-Z]+\])?\s*/mi',
        '',
        $description
    ) ?? $description;

    // Remove Markdown formatting.
    $description = str_replace(
        ['**', '__', '`'],
        '',
        $description
    );

    // Convert repeated whitespace into one space.
    $description = preg_replace(
        '/\s+/',
        ' ',
        $description
    ) ?? $description;

    $description = trim($description);

    if (mb_strlen($description) > $maxLength) {
        $description = mb_substr(
            $description,
            0,
            $maxLength
        );

        $description = rtrim(
            $description,
            " \t\n\r\0\x0B.,;:-"
        );

        $description .= '...';
    }

    return $description;
}

function formatThreatDate(?string $date): string
{
    if ($date === null || trim($date) === '') {
        return 'Unknown';
    }

    try {
        return (new DateTimeImmutable($date))->format('Y-m-d');
    } catch (Exception) {
        return $date;
    }
}

$cleanedDescription = cleanFullDescription(
    $event['description'] ?? null
);

$sourceLinks = [];

if (!empty($event['source_links'])) {
    foreach (explode('||', $event['source_links']) as $item) {
        $parts = explode('|', $item, 2);

        if (count($parts) !== 2) {
            continue;
        }

        [$name, $url] = $parts;

        $name = trim($name);
        $url = trim($url);

        if ($name === '' || $url === '') {
            continue;
        }

        $sourceLinks[] = [
            'name' => $name,
            'url' => $url,
        ];
    }
}

$severityClass = strtolower($event['severity'] ?? '');

?>

<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">

    <meta
        name="viewport"
        content="width=device-width, initial-scale=1.0"
    >

    <title>
        <?= htmlspecialchars(
            (string) $event['cve_id'],
            ENT_QUOTES,
            'UTF-8'
        ) ?>
        - Open Threat Hub
    </title>

    <style>
        body {
            margin: 0;
            font-family: Arial, sans-serif;
            background: #f3f4f6;
            color: #111827;
        }

        header {
            background: #111827;
            color: white;
            padding: 24px;
        }

        main {
            width: min(900px, 92%);
            margin: 30px auto;
        }

        .back-link {
            display: inline-block;
            margin-bottom: 20px;
            color: #2563eb;
            text-decoration: none;
        }

        .back-link:hover {
            text-decoration: underline;
        }

        .card {
            background: white;
            border-radius: 12px;
            padding: 28px;
            box-shadow: 0 2px 8px rgba(0, 0, 0, 0.08);
        }

        h1 {
            margin: 0 0 12px;
        }

        h2 {
            margin: 0;
            font-size: 22px;
            line-height: 1.4;
        }

        .metadata {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 20px 0;
        }

        .badge {
            background: #e5e7eb;
            padding: 6px 10px;
            border-radius: 14px;
            font-size: 14px;
        }

        .critical {
            background: #fee2e2;
        }

        .high {
            background: #ffedd5;
        }

        .medium {
            background: #fef3c7;
        }

        .low {
            background: #dcfce7;
        }

        .description {
            margin-top: 24px;
            line-height: 1.7;
            text-align: left;
            overflow-wrap: anywhere;
        }

        .sources {
            margin-top: 28px;
        }

        .sources h3 {
            margin-bottom: 8px;
        }

        .source-item {
            padding: 14px 0;
            border-bottom: 1px solid #e5e7eb;
        }

        .source-item:last-child {
            border-bottom: 0;
        }

        .source-item strong {
            display: block;
            margin-bottom: 7px;
        }

        .source-item a {
            display: inline-block;
            color: #2563eb;
            text-decoration: none;
        }

        .source-item a:hover {
            text-decoration: underline;
        }

        .dates {
            margin-top: 28px;
            padding-top: 20px;
            border-top: 1px solid #e5e7eb;
            color: #4b5563;
            line-height: 1.8;
        }

       .priority {
            display: inline-block;
            padding: 5px 9px;
            border-radius: 12px;
            font-size: 13px;
            font-weight: 600;
        }
        
        .priority-urgent {
            background: #dc2626;
            color: white;
        }
        
        .priority-high {
            background: #ea580c;
            color: white;
        }
        
        .priority-medium {
            background: #eab308;
            color: black;
        }
        
        .priority-low {
            background: #16a34a;
            color: white;
        } 

    </style>
</head>

<body>
<header>
    <strong>Open Threat Hub</strong>
</header>

<main>
    <a class="back-link" href="dashboard.php">
        ← Back to dashboard
    </a>

    <article class="card">
        <h1>
            <?= htmlspecialchars(
                (string) $event['cve_id'],
                ENT_QUOTES,
                'UTF-8'
            ) ?>
        </h1>

        <h2>
            <?= htmlspecialchars(
                (string) $event['title'],
                ENT_QUOTES,
                'UTF-8'
            ) ?>
        </h2>

        <div class="metadata">
            <?php if (!empty($event['severity'])): ?>
                <span class="badge <?= htmlspecialchars($severityClass) ?>">
                    Severity:
                    <?= htmlspecialchars(
                        (string) $event['severity'],
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?>
                </span>
            <?php endif; ?>

            <span class="priority priority-<?= strtolower($priority['priority']) ?>">
                Priority: <?= htmlspecialchars($priority['priority']) ?>
                (<?= (int) $priority['score'] ?>)
            </span>

            <?php if ($event['cvss'] !== null): ?>
                <span class="badge">
                    CVSS:
                    <?= htmlspecialchars(
                        (string) $event['cvss'],
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?>
                </span>
            <?php endif; ?>

            <?php if (!empty($event['sources'])): ?>
                <span class="badge">
                    Sources:
                    <?= htmlspecialchars(
                        (string) $event['sources'],
                        ENT_QUOTES,
                        'UTF-8'
                    ) ?>
                </span>
            <?php endif; ?>
        </div>

        <?php if ($cleanedDescription !== ''): ?>
            <div class="description">
                <?= nl2br(
                    htmlspecialchars(
                        $cleanedDescription,
                        ENT_QUOTES,
                        'UTF-8'
                    )
                ) ?>
            </div>
        <?php endif; ?>

        <?php if ($sourceLinks !== []): ?>
            <div class="sources">
                <h3>Sources</h3>

                <?php foreach ($sourceLinks as $sourceLink): ?>
                    <div class="source-item">
                        <strong>
                            <?= htmlspecialchars(
                                $sourceLink['name'],
                                ENT_QUOTES,
                                'UTF-8'
                            ) ?>
                        </strong>

                        <a
                            href="<?= htmlspecialchars(
                                $sourceLink['url'],
                                ENT_QUOTES,
                                'UTF-8'
                            ) ?>"
                            target="_blank"
                            rel="noopener noreferrer"
                        >
                            Open advisory
                        </a>
                    </div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <div class="dates">
            <div>
                First seen:
                <?= htmlspecialchars(
                    formatThreatDate(
                        $event['first_seen'] ?? null
                    ),
                    ENT_QUOTES,
                    'UTF-8'
                ) ?>
            </div>

            <div>
                Last seen:
                <?= htmlspecialchars(
                    formatThreatDate(
                        $event['last_seen'] ?? null
                    ),
                    ENT_QUOTES,
                    'UTF-8'
                ) ?>
            </div>
        </div>
    </article>
</main>
</body>
</html>
