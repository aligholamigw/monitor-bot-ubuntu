<?php
declare(strict_types=1);
if (PHP_SAPI !== 'cli') { http_response_code(404); exit; }
require dirname(__DIR__) . '/src/bootstrap.php';
umask(0077);
try {
    [$config, $store, $api] = application();
    $runner = fopen($config['data_dir'] . '/runner.lock', 'c');
    if (!$runner || !flock($runner, LOCK_EX | LOCK_NB)) { exit(0); }
    unset($store, $api);
    // One bounded minute slice. Sleep without the state lock, so webhooks can respond.
    $until = microtime(true) + 50;
    do {
        $iteration = microtime(true);
        try {
            [$config, $store, $api] = application(max(0.5, min(32, $until - microtime(true))));
            $app = new App($config, $store, $api);
            $now = time();
            if ($now - ($app->state['last_monitor_poll'] ?? 0) >= 60 || $app->state['live']['needs_monitor']) {
                $app->state['last_monitor_poll'] = $now;
                $app->state['live']['needs_monitor'] = false;
                $app->tick($now);
            }
            $app->liveStep(time());
            $app->flush();
        } catch (Throwable $e) {
            if ($e->getMessage() !== 'BUSY') { throw $e; }
        } finally { unset($app, $store, $api); }
        $sleep = max(0, 10 - (microtime(true) - $iteration));
        if (microtime(true) + $sleep + 0.5 >= $until) { break; }
        if ($sleep > 0) { usleep((int)($sleep * 1000000)); }
    } while (microtime(true) < $until);
} catch (Throwable $e) {
    if ($e->getMessage() === 'BUSY') { exit(0); }
    fwrite(STDERR, date('c') . ' Cron failed (' . get_class($e) . "). Check configuration, data directory and APIs.\n");
    exit(1);
}
