<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }

require dirname(__DIR__) . '/src/bootstrap.php';
umask(0077);
[$config, $store] = application();
if (($config['telegram_mode'] ?? '') !== 'polling') {
    fwrite(STDERR, "Set telegram_mode to polling.\n");
    exit(1);
}
$lock = fopen($config['data_dir'] . '/poll.lock', 'c');
if (!$lock || !flock($lock, LOCK_EX | LOCK_NB)) { exit(0); }
unset($store);

// Keep the offset in memory. App::command records each admin update durably.
// Telegram retries unconfirmed updates after restarts, and the App deduplicates them.
$offset = null;
$lastUpdate = time();
$lastError = null;
while (true) {
    try {
        $request = ['limit' => 15, 'timeout' => 6, 'allowed_updates' => ['message', 'callback_query']];
        // After a week of inactivity Telegram may start a different update ID sequence.
        if ($offset !== null && time() - $lastUpdate < 6 * 86400) { $request['offset'] = $offset; }
        $response = (new Network($config, 12))->telegram('getUpdates', $request);
        $updates = $response['result'] ?? null;
        if (!is_array($updates)) { throw new RuntimeException('Invalid Telegram updates response.'); }
        if ($lastError !== null) {
            error_log('Telegram polling reconnected.');
            $lastError = null;
        }
        foreach ($updates as $update) {
            if (!is_array($update) || !is_int($update['update_id'] ?? null)) { continue; }
            try {
                $store = new Store($config['data_dir']);
                $app = new App($config, $store, new Network($config, 30));
                $app->command($update);
                $app->flush();
                $offset = $update['update_id'] + 1;
                $lastUpdate = time();
            } finally {
                unset($app, $store);
            }
        }
    } catch (Throwable $error) {
        // A cron-held lock is temporary. Preserve the offset for the unprocessed update.
        if ($error->getMessage() === 'BUSY') { usleep(500000); continue; }
        $reason = $error instanceof HttpFailure ? $error->getMessage() : get_class($error);
        if ($reason !== $lastError) {
            error_log('Telegram polling failed: ' . $reason . ($error instanceof HttpFailure && $error->status === 409
                ? ' (check for an active webhook or another poller)' : ''));
            $lastError = $reason;
        }
        sleep($error instanceof HttpFailure ? max(3, min(60, $error->retryAfter)) : 3);
    }
}
