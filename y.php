<?php
function scan_directory($dir) {
    $rii = new RecursiveIteratorIterator(new RecursiveDirectoryIterator($dir));
    $malicious_patterns = [
        '/eval\s*\(/i',
        '/base64_decode\s*\(/i',
        '/gzinflate\s*\(/i',
        '/shell_exec\s*\(/i',
        '/system\s*\(/i',
        '/passthru\s*\(/i',
        '/exec\s*\(/i',
        '/`.*`/',  // backtick execution
        '/curl_exec\s*\(/i',
        '/file_get_contents\s*\(.*http/i',
        '/fopen\s*\(.*http/i'
    ];

    foreach ($rii as $file) {
        if ($file->isDir()) continue;
        if (pathinfo($file, PATHINFO_EXTENSION) !== 'php') continue;

        $contents = file_get_contents($file->getPathname());
        foreach ($malicious_patterns as $pattern) {
            if (preg_match($pattern, $contents)) {
                echo "[Suspicious] " . $file->getPathname() . "\n";
                break;
            }
        }
    }
}

// Set this to the root directory of your website
scan_directory(__DIR__);
?>