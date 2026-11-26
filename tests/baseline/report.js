#!/usr/bin/env node
'use strict';

// Builds the summary (JSON + Markdown table) and benchstat-compatible text
// from the raw measurement files.
//
//   node tests/baseline/report.js --name 2026-11-26-baseline-python
//
// For a later comparison, run the same measurements against the new backend
// and compare the two .bench.txt files with benchstat.

const fs = require('node:fs');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..');
const BASELINE_DIR = path.join(REPO_ROOT, 'plans', 'baseline');
const RAW_DIR = path.join(BASELINE_DIR, 'raw');

function latest(prefix) {
    const files = fs.existsSync(RAW_DIR) ? fs.readdirSync(RAW_DIR).filter((name) => name.startsWith(prefix) && name.endsWith('.json')).sort() : [];
    return files.length ? { file: `raw/${files.at(-1)}`, data: JSON.parse(fs.readFileSync(path.join(RAW_DIR, files.at(-1)), 'utf8')) } : null;
}

const get = (object, keys) => keys.split('.').reduce((value, key) => (value == null ? undefined : value[key]), object);
const fmt = (value, digits = 1) => (value == null || Number.isNaN(value) ? 'n/a' : Number(value).toFixed(digits));

function pair(run, keys, digits, scale = 1) {
    const stats = get(run, keys);
    if (!stats || stats.median == null) return 'nicht gemessen';
    if (keys.endsWith('mib_per_s')) return `${fmt(stats.median * scale, digits)} (min ${fmt(stats.min * scale, digits)}, n=${stats.n})`;
    return `${fmt(stats.median * scale, digits)} / ${fmt(stats.p95 * scale, digits)} (n=${stats.n})`;
}

function phaseError(run, phase) {
    const error = get(run, `phases.${phase}.error`);
    return error ? `Fehler: ${String(error).split('\n')[0]}` : null;
}

function cell(run, phase, keys, digits, scale) {
    if (!run) return 'nicht gemessen';
    if (run.target === 'local' && keys.includes('container_mib')) return 'entfällt (kein Container)';
    return phaseError(run, phase) || pair(run, `phases.${phase}.${keys}`, digits, scale);
}

function rows(docker, local) {
    const both = (label, phase, keys, digits, scale, method) => [label, cell(docker?.data, phase, keys, digits, scale), cell(local?.data, phase, keys, digits, scale), method];
    return [
        both('Start bis /ready, leeres Datenverzeichnis [ms]', 'startup', 'cold_empty_data_dir_ms', 0, 1, 'docker run bzw. gunicorn-Start bis HTTP 200, Abfrage alle 20 ms'),
        both('Start bis /ready, vorhandenes Datenverzeichnis [ms]', 'startup', 'warm_existing_data_dir_ms', 0, 1, 'neuer Container bzw. Prozess auf denselben Daten'),
        both('RSS Leerlauf, Standardgrenzen [MiB]', 'memory', 'summary.default.idle.rss_total_mib', 1, 1, 'Summe VmRSS des Prozessbaums, Median je Lauf'),
        both('Container-Speicher Leerlauf, Standardgrenzen [MiB]', 'memory', 'summary.default.idle.container_mib', 1, 1, 'docker stats (cgroup, ohne Page Cache)'),
        both('RSS mit 10 Terminals, Standardgrenzen [MiB]', 'memory', 'summary.default.sessions_10.rss_total_mib', 1, 1, '2 Konten x 1 Socket x 5 Terminals'),
        both('Container-Speicher mit 10 Terminals [MiB]', 'memory', 'summary.default.sessions_10.container_mib', 1, 1, ''),
        both('RSS Leerlauf, Quote 40 [MiB]', 'memory', 'summary.raised_quota.idle.rss_total_mib', 1, 1, 'QUOTA_SSH_SESSION_GLOBAL=40'),
        both('RSS mit 40 Terminals, Quote 40 [MiB]', 'memory', 'summary.raised_quota.sessions_40.rss_total_mib', 1, 1, '8 Konten x 1 Socket x 5 Terminals'),
        both('Container-Speicher mit 40 Terminals [MiB]', 'memory', 'summary.raised_quota.sessions_40.container_mib', 1, 1, ''),
        both('Threads mit 40 Terminals', 'memory', 'summary.raised_quota.sessions_40.threads_total', 0, 1, 'Summe Threads des Prozessbaums'),
        both('Echo-Round-Trip [ms]', 'terminal', 'echo_rtt.ms', 2, 1, 'ein Zeichen per ssh_input bis zum Echo in ssh_output'),
        both('cat 50 MiB, Dauer [s]', 'terminal', 'cat_50mib.seconds', 2, 1, 'Enter bis Endmarke; Ausgabe sofort quittiert'),
        both('cat 50 MiB, Durchsatz [MiB/s]', 'terminal', 'cat_50mib.mib_per_s', 1, 1, 'Dateigröße / Dauer; Median und langsamster Lauf'),
        both('SFTP-Upload 200 MiB, Dauer [s]', 'sftp', 'upload_200mib.seconds', 1, 1, 'MAX_UPLOAD_SIZE=256 MiB'),
        both('SFTP-Upload 200 MiB [MiB/s]', 'sftp', 'upload_200mib.mib_per_s', 1, 1, 'prepare_transfer + HTTP POST, sha256 geprüft'),
        both('SFTP-Download 200 MiB, Dauer [s]', 'sftp', 'download_200mib.seconds', 1, 1, 'MAX_DOWNLOAD_SIZE=256 MiB'),
        both('SFTP-Download 200 MiB [MiB/s]', 'sftp', 'download_200mib.mib_per_s', 1, 1, 'prepare_transfer + HTTP GET, sha256 geprüft'),
    ];
}

function limitsText(run, label) {
    const limits = get(run?.data, 'phases.limits');
    if (!limits) return [`- ${label}: nicht gemessen`];
    if (limits.error) return [`- ${label}: Fehler: ${limits.error.split('\n')[0]}`];
    const first = limits.sockets.first_rejection;
    const byUser = new Map();
    for (const item of limits.ssh_sessions.attempts) {
        const entry = byUser.get(item.user) || { connected: 0, refused: [] };
        if (item.result === 'connected') entry.connected += 1;
        else entry.refused.push(item.result);
        byUser.set(item.user, entry);
    }
    const quotaText = [...byUser].map(([user, entry]) => `${user}: ${entry.connected} verbunden, ${entry.refused.length} abgelehnt`).join('; ');
    const refusal = limits.ssh_sessions.attempts.find((item) => item.result !== 'connected')?.result ?? '-';
    const transfer = limits.transfer_size_default;
    return [
        `- ${label}: ${limits.sockets.held} Sockets gehalten; Versuch ${first?.number ?? 'keiner'} abgelehnt mit \`${first?.result ?? '-'}\` (HTTP ${first?.description ?? '-'} beim Engine.IO-Handshake); /ready währenddessen ${fmt(limits.sockets.ready_while_held.ms.median, 2)} ms Median, ${limits.sockets.ready_while_held.failures.length} Fehler${limits.sockets.ready_while_held.failures.length ? ` (${limits.sockets.ready_while_held.failures.join(', ')})` : ''}; nach Freigabe eines Sockets: ${limits.sockets.reopen_after_release}.`,
        `- ${label}: SSH-Sitzungen mit Standardquote (je Konto 6 Versuche): ${quotaText}; insgesamt ${limits.ssh_sessions.connected} verbunden; Meldung \`${refusal}\`.`,
        `- ${label}: 200 MiB mit Standardgrenzen: Upload HTTP ${transfer.upload_200mib?.status ?? '-'} \`${(transfer.upload_200mib?.body || '').trim()}\`, Download HTTP ${transfer.download_200mib?.status ?? '-'} \`${(transfer.download_200mib?.body || '').trim()}\`.`,
    ];
}

function benchLines(run) {
    if (!run) return [];
    const target = run.data.target;
    const lines = [];
    const push = (name, values, unit, scale = 1) => {
        for (const value of values || []) lines.push(`Benchmark${name}/target=${target} 1 ${(value * scale).toFixed(0)} ${unit}`);
    };
    const phases = run.data.phases;
    push('StartupCold', phases.startup?.samples?.cold, 'ns/op', 1e6);
    push('StartupWarm', phases.startup?.samples?.warm, 'ns/op', 1e6);
    push('EchoRTT', phases.terminal?.echo_rtt?.samples, 'ns/op', 1e6);
    push('Cat50MiB', phases.terminal?.cat_50mib?.runs?.map((item) => item.seconds), 'ns/op', 1e9);
    push('SFTPUpload200MiB', phases.sftp?.upload_200mib?.runs?.filter((item) => item.ok).map((item) => item.seconds), 'ns/op', 1e9);
    push('SFTPDownload200MiB', phases.sftp?.download_200mib?.runs?.filter((item) => item.ok).map((item) => item.seconds), 'ns/op', 1e9);
    for (const [config, data] of Object.entries(phases.memory?.runs || {})) {
        for (const runData of data) {
            for (const [key, value] of Object.entries(runData)) {
                lines.push(`BenchmarkRSS/target=${target}/limits=${config}/load=${key} 1 ${(value.rss_total_mib * 1048576).toFixed(0)} B/op`);
            }
        }
    }
    return lines;
}

function main() {
    const nameIndex = process.argv.indexOf('--name');
    const name = nameIndex === -1 ? 'baseline' : process.argv[nameIndex + 1];
    const docker = latest('docker-');
    const local = latest('local-');
    const image = latest('image-');
    const e2e = latest('e2e-');
    const host = (docker || local)?.data.host;
    const lines = [
        `# Baseline ${name}`,
        '',
        'Erzeugt mit `node tests/baseline/report.js` aus den Rohdaten der Messläufe.',
        '',
        '## Umgebung',
        '',
        `- CPU: ${host?.cpu_model} (${host?.logical_cpus} logische Kerne), RAM ${host?.memory_total_mib} MiB`,
        `- OS: ${host?.os_release}; \`${host?.uname}\``,
        `- Docker ${host?.docker} (Kontext \`${host?.docker_context}\`), Node ${host?.node}, ${host?.venv_python} (.venv)`,
        `- Image: \`${docker?.data.image?.digest ?? 'n/a'}\` (Revision ${docker?.data.image?.revision ?? 'n/a'})`,
        `- SSH-Ziel: \`${(docker || local)?.data.sshd_image}\``,
        `- Last (loadavg 1/5/15) Docker-Lauf: ${docker ? `${docker.data.loadavg_start.map((v) => v.toFixed(2)).join(' ')} -> ${docker.data.loadavg_end.map((v) => v.toFixed(2)).join(' ')}` : 'n/a'}; lokal: ${local ? `${local.data.loadavg_start.map((v) => v.toFixed(2)).join(' ')} -> ${local.data.loadavg_end.map((v) => v.toFixed(2)).join(' ')}` : 'n/a'}`,
        `- Rohdaten: ${[docker, local, image, e2e].filter(Boolean).map((item) => `\`${item.file}\``).join(', ')}`,
        '',
        '## Messwerte (Median / p95, n = Anzahl Messungen; Durchsatz: Median und Minimum)',
        '',
        '| Größe | Docker (Image) | Lokal (.venv) | Methode |',
        '|---|---|---|---|',
        ...rows(docker, local).map((row) => `| ${row.join(' | ')} |`),
        '',
        '## Grenzen',
        '',
        ...limitsText(docker, 'Docker'),
        ...limitsText(local, 'Lokal'),
        '',
        '## Image',
        '',
    ];
    if (image) {
        const data = image.data;
        lines.push(
            '| Größe | Wert |',
            '|---|---|',
            `| Plattform | ${data.platform} (\`${data.platform_manifest_digest}\`) |`,
            `| Unkomprimiert | ${(data.uncompressed_bytes / 1e6).toFixed(1)} MB (${data.uncompressed_bytes} Bytes) |`,
            `| Komprimiert (Layer + Config laut Manifest) | ${(data.compressed_bytes / 1e6).toFixed(1)} MB (${data.compressed_bytes} Bytes) |`,
            `| Layer | ${data.layer_count} |`,
            `| Debian-Pakete (dpkg) | ${data.debian_packages} |`,
            `| Python-Distributionen | ${data.python_distributions} |`,
            '',
        );
    } else {
        lines.push('nicht gemessen', '');
    }
    lines.push('## E2E-Suite', '');
    if (e2e) {
        const data = e2e.data;
        lines.push(
            `- Befehl: \`${data.command}\``,
            `- Wanduhrzeit: ${(data.wall_seconds / 60).toFixed(1)} min (${data.wall_seconds.toFixed(0)} s), Exit-Code ${data.exit_code}`,
            `- Ergebnis: ${data.passed} bestanden, ${data.failed} fehlgeschlagen, ${data.flaky} flaky, ${data.skipped} übersprungen, ${data.did_not_run} nicht gelaufen`,
            '',
        );
    } else {
        lines.push('nicht gemessen', '');
    }
    const summary = { name, generated_at: new Date().toISOString(), sources: [docker, local, image, e2e].filter(Boolean).map((item) => item.file), host, rows: rows(docker, local).map(([label, dockerValue, localValue]) => ({ label, docker: dockerValue, local: localValue })), image: image?.data && { ...image.data, packages: undefined }, e2e: e2e?.data && { ...e2e.data, output_tail: undefined } };
    fs.writeFileSync(path.join(BASELINE_DIR, `${name}.md`), `${lines.join('\n')}\n`);
    fs.writeFileSync(path.join(BASELINE_DIR, `${name}.json`), `${JSON.stringify(summary, null, 2)}\n`);
    fs.writeFileSync(path.join(BASELINE_DIR, `${name}.bench.txt`), `${[...benchLines(docker), ...benchLines(local)].join('\n')}\n`);
    process.stderr.write(`[baseline] wrote ${name}.md, ${name}.json, ${name}.bench.txt\n`);
}

main();
