(function () {
    'use strict';
    const t = key => window.i18n.t(`supportReport.${key}`);
    const root = (document.querySelector('meta[name="app-root"]')?.content || '').replace(/\/$/, '');
    const csrf = document.querySelector('meta[name="csrf-token"]')?.content || '';
    function node(tag, text, className) {
        const element = document.createElement(tag);
        if (text) element.textContent = text;
        if (className) element.className = className;
        return element;
    }
    function openReport(event) {
        if (document.querySelector('.support-report-dialog')) return;
        const trigger = event.currentTarget;
        const dialog = node('dialog', '', 'support-report-dialog');
        dialog.setAttribute('aria-labelledby', 'supportReportTitle');
        const header = node('header', '', 'support-report-header');
        const title = node('h2', t('title')); title.id = 'supportReportTitle';
        const close = node('button', t('close'), 'btn btn-secondary'); close.type = 'button';
        close.addEventListener('click', () => dialog.close());
        header.append(title, close);
        const body = node('div', '', 'support-report-body');
        body.append(node('p', t('hint'), 'admin-muted'));
        const form = node('form', '', 'support-report-form');
        const areaLabel = node('label', t('area')); areaLabel.htmlFor = 'supportReportArea';
        const area = node('select', '', 'form-control'); area.id = 'supportReportArea';
        for (const value of ['general', 'ssh', 'files', 'sign_in', 'automation']) {
            const option = node('option', t(value)); option.value = value; area.append(option);
        }
        const referenceLabel = node('label', t('reference')); referenceLabel.htmlFor = 'supportReportReference';
        const reference = node('input', '', 'form-control'); reference.id = 'supportReportReference';
        reference.type = 'text'; reference.maxLength = 16; reference.autocomplete = 'off'; reference.spellcheck = false;
        reference.placeholder = 'SMB-ABCDEF123456'; reference.pattern = 'SMB-[A-F0-9]{12}';
        reference.setAttribute('aria-describedby', 'supportReportReferenceHint');
        const referenceHint = node('p', t('referenceHint'), 'admin-muted'); referenceHint.id = 'supportReportReferenceHint';
        const generate = node('button', t('generate'), 'btn btn-primary'); generate.type = 'submit';
        form.append(areaLabel, area, referenceLabel, reference, referenceHint, generate);
        const status = node('p', '', 'support-report-status'); status.setAttribute('role', 'status');
        const preview = node('section'); preview.hidden = true;
        const previewLabel = node('h3', t('preview')); previewLabel.id = 'supportReportPreviewTitle';
        const content = node('pre'); content.tabIndex = 0; content.setAttribute('aria-labelledby', previewLabel.id);
        preview.append(previewLabel, content); body.append(form, status, preview);
        const footer = node('footer', '', 'support-report-footer');
        const copy = node('button', t('copy'), 'btn btn-secondary'); copy.type = 'button'; copy.disabled = true;
        const download = node('button', t('download'), 'btn btn-secondary'); download.type = 'button'; download.disabled = true;
        footer.append(copy, download); dialog.append(header, body, footer);
        let report = '';
        let controller;
        const clearPreview = () => {
            report = ''; content.textContent = ''; preview.hidden = true;
            copy.disabled = download.disabled = true; status.textContent = '';
        };
        form.addEventListener('input', clearPreview);
        form.addEventListener('change', clearPreview);
        form.addEventListener('submit', async submit => {
            submit.preventDefault();
            if (controller) return;
            clearPreview(); controller = new AbortController();
            const timeout = setTimeout(() => controller?.abort(), 10000);
            generate.disabled = area.disabled = reference.disabled = true;
            status.textContent = t('loading');
            try {
                const response = await fetch(`${root}/api/account/support-report`, {
                    method: 'POST', cache: 'no-store', signal: controller.signal,
                    headers: {'Content-Type': 'application/json', 'X-CSRFToken': csrf},
                    body: JSON.stringify({area: area.value, reference: reference.value.trim()}),
                });
                if (!response.ok) throw new Error('Report unavailable');
                const data = await response.json();
                if (!dialog.open) return;
                if (data.schema !== 1 || !data.features || !data.readiness) throw new Error('Invalid report');
                report = JSON.stringify(data, null, 2);
                content.textContent = report; preview.hidden = false;
                copy.disabled = download.disabled = false; status.textContent = t('ready');
                content.focus({preventScroll: true});
                body.scrollTop = preview.offsetTop - body.offsetTop;
            } catch {
                if (dialog.open) status.textContent = t('failed');
            } finally {
                clearTimeout(timeout); controller = null;
                generate.disabled = area.disabled = reference.disabled = false;
            }
        });
        copy.addEventListener('click', async () => {
            if (!report) return;
            try {
                if (!navigator.clipboard?.writeText) throw new Error('Clipboard unavailable');
                await navigator.clipboard.writeText(report + '\n'); status.textContent = t('copied');
            } catch { status.textContent = t('copyFailed'); }
        });
        download.addEventListener('click', () => {
            if (!report) return;
            const url = URL.createObjectURL(new Blob([report + '\n'], {type: 'application/json;charset=utf-8'}));
            const link = node('a'); link.href = url; link.download = 'webssh-support-report.json';
            document.body.append(link); link.click(); link.remove();
            setTimeout(() => URL.revokeObjectURL(url), 1000);
        });
        dialog.addEventListener('close', () => {
            controller?.abort(); report = ''; dialog.remove(); trigger.focus();
        }, {once: true});
        document.body.append(dialog); dialog.showModal(); area.focus();
    }
    document.querySelectorAll('[data-support-report]').forEach(button => button.addEventListener('click', openReport));
}());
