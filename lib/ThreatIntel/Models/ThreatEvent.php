<?php

namespace ThreatIntel\Models;

final class ThreatEvent
{
    public string $cveId;
    public string $title;

    /** @var array<int,string> */
    public array $sources = [];

    /** @var array<int,array> */
    public array $items = [];

    public ?string $severity = null;
    public ?float $cvss = null;
    public ?string $description = null;
    public int $timestamp;


    public function __construct(
        string $cveId,
        string $title
    ) {
        $this->cveId = $cveId;
        $this->title = $title;
        $this->timestamp = time();
    }


    public function addSource(string $source): void
    {
        if (!in_array($source, $this->sources)) {
            $this->sources[] = $source;
        }
    }
}
