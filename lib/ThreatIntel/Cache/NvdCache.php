<?php

namespace ThreatIntel\Cache;

final class NvdCache
{
    private string $dir;

    public function __construct()
    {
        $this->dir = __DIR__ . '/../../../../cache/nvd';

        if (!is_dir($this->dir)) {
            mkdir($this->dir, 0777, true);
        }
    }


    public function get(string $cve): ?array
    {
        $file = $this->dir . '/' . strtoupper($cve) . '.json';

        if (!file_exists($file)) {
            return null;
        }


        if (time() - filemtime($file) > 86400) {
            return null;
        }


        $data = json_decode(
            file_get_contents($file),
            true
        );


        return is_array($data) ? $data : null;
    }


    public function set(string $cve, array $data): void
    {
        $file = $this->dir . '/' . strtoupper($cve) . '.json';

        file_put_contents(
            $file,
            json_encode($data, JSON_PRETTY_PRINT)
        );
    }
}
