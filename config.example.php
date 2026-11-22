<?php
declare(strict_types=1);
return [
    'telegram_mode' => 'webhook',
    // Keep this directory OUTSIDE public_html. See README.fa.md.
    'data_dir' => __DIR__ . '/var',
    'monitor_url' => 'http://MONITOR_HOST:PORT/api/u/CHANGE_ME/status?hours=1',
    'source_name' => 'sub.zarvanta.com',
    'monitor_socks_proxy' => '', // Optional: socks5h://host:port, or credentials in this private file only.
    'domains' => ['ip1.arvesta.ir', 'ip2.arvesta.ir'],
    'workers' => ['mci-thr', 'mkh-thr'],
    'failure_threshold' => 3,       // /threshold 2 or /threshold 3
    'operator_policy' => 'any',     // any: either operator; all: both operators
    'red_statuses' => ['down', 'blocked'],
    'max_sample_age' => 300,
    'max_sample_gap' => 360,
    'cooldown_seconds' => 600,
    'dns_grace_seconds' => 180,
    'low_pool_threshold' => 5,
    'alert_repeat_seconds' => 21600,
    'require_live_preflight' => true,
    'live_template' => 'vless://CHANGE_ME@ip1.arvesta.ir:2053?security=tls&type=xhttp&sni=YOUR_SNI&host=YOUR_HOST&path=%2F',
    'live_workers' => ['mtn-mashhad', 'mci-thr', 'mkh-thr', 'mtn-asiatech'],
    'live_checks' => ['upload', 'download', 'jitter'],
    'live_interval_seconds' => 10,
    'live_hourly_limit' => 60,
    'live_scan_reserve' => 10, // Keep hourly capacity for pre-DNS validation.
    'live_job_timeout' => 180,
    'live_proof_max_age' => 180,
    'scan_max_addresses' => 65536, // Lazy cursor, not an array of all IPs.
    'scan_max_ranges' => 16,
    'scan_report_seconds' => 300,
    'cloudflare_token' => 'CHANGE_ME', // DNS Edit limited to arvesta.ir
    'cloudflare_zone_id' => 'CHANGE_ME',
    'telegram_token' => 'CHANGE_ME',
    'admin_user_ids' => ['CHANGE_ME'], // Numeric Telegram USER IDs, not usernames
    'telegram_chat_id' => 'CHANGE_ME', // Private chat with the admin
    'webhook_secret' => 'CHANGE_ME',  // Generate with: php bin/console.php secret
    'webhook_url' => 'https://YOUR-DOMAIN.example/monitor-bot/webhook.php',
    // First start in simulation. /live + /resume enable real changes.
    'initial_dry_run' => true,
    'initial_paused' => true,
];
