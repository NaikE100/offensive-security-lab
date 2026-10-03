<?php
/**
 * Threat Intelligence & Telemetry Logger
 * 
 * Part of the Defensive Telemetry Suite for TrueSelf.
 * Captures incoming HTTP request metrics, resolves actual client IPs through 
 * reverse proxies, audits security header compliance, and logs anomalous activity.
 * 
 * @author  Egan Naik
 * @license MIT
 */

declare(strict_types=1);

class ThreatLedgerLogger 
{
    private array $requiredHeaders = [
        'HTTP_STRICT_TRANSPORT_SECURITY',
        'HTTP_CONTENT_SECURITY_POLICY',
        'HTTP_X_FRAME_OPTIONS',
        'HTTP_REFERRER_POLICY'
    ];

    /**
     * Resolves the real client IP address, handling edge networks, Cloudflare,
     * and reverse proxy forwarded headers safely.
     */
    public function getClientIp(): string 
    {
        $ipSources = [
            'HTTP_CF_CONNECTING_IP', // Cloudflare
            'HTTP_X_REAL_IP',        // NGINX / LiteSpeed Reverse Proxy
            'HTTP_X_FORWARDED_FOR',  // Standard Forwarded Header
            'REMOTE_ADDR'            // Direct Socket Connection
        ];

        foreach ($ipSources as $source) {
            if (!empty($_SERVER[$source])) {
                // Handle multiple IP lists in X-Forwarded-For (client, proxy1, proxy2)
                $ipList = explode(',', $_SERVER[$source]);
                $clientIp = trim($ipList[0]);

                if (filter_var($clientIp, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE)) {
                    return $clientIp;
                }
            }
        }

        return $_SERVER['REMOTE_ADDR'] ?? '127.0.0.1';
    }

    /**
     * Evaluates current HTTP response header coverage.
     */
    public function auditSecurityHeaders(array $responseHeaders): array 
    {
        $auditResults = [];
        $missingCount = 0;

        $headersToAudit = [
            'Strict-Transport-Security',
            'Content-Security-Policy',
            'Permissions-Policy',
            'Referrer-Policy'
        ];

        foreach ($headersToAudit as $header) {
            $isSet = isset($responseHeaders[$header]) || isset($responseHeaders[strtolower($header)]);
            $auditResults[$header] = $isSet ? 'PASS' : 'MISSING';
            if (!$isSet) {
                $missingCount++;
            }
        }

        // Calculate basic baseline score
        $total = count($headersToAudit);
        $score = (int) ((($total - $missingCount) / $total) * 100);

        return [
            'score' => $score,
            'details' => $auditResults
        ];
    }

    /**
     * Sanitizes and packages request telemetry for database ingestion.
     */
    public function captureTelemetry(): array 
    {
        return [
            'timestamp'   => date('Y-m-d H:i:s'),
            'client_ip'   => $this->getClientIp(),
            'user_agent'  => htmlspecialchars($_SERVER['HTTP_USER_AGENT'] ?? 'Unknown', ENT_QUOTES, 'UTF-8'),
            'uri'         => htmlspecialchars($_SERVER['REQUEST_URI'] ?? '/', ENT_QUOTES, 'UTF-8'),
            'method'      => $_SERVER['REQUEST_METHOD'] ?? 'GET',
            'is_suspicious' => $this->detectAnomaly()
        ];
    }

    /**
     * Basic pattern matching for automated scanning tools.
     */
    private function detectAnomaly(): bool 
    {
        $userAgent = strtolower($_SERVER['HTTP_USER_AGENT'] ?? '');
        $signatures = ['sqlmap', 'nikto', 'burp', 'nmap', 'masscan', 'gobuster', 'w預uzz'];

        foreach ($signatures as $pattern) {
            if (str_contains($userAgent, $pattern)) {
                return true;
            }
        }

        return false;
    }
}
