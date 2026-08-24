(function exposeFileWorkspaceState(globalObject) {
    const PANES = new Set(['left', 'right']);
    const LAYOUTS = new Set(['single', 'split']);
    const SOURCE_FIELDS = [
        'sourceId',
        'kind',
        'label',
        'endpoint',
        'protocol',
        'capabilities',
        'ephemeral',
        'status',
        'security',
    ];

    class FileWorkspaceState {
        constructor(createPaneState) {
            if (typeof createPaneState !== 'function') {
                throw new TypeError('FileWorkspaceState requires a pane-state factory');
            }
            this.createPaneState = createPaneState;
            this.layout = 'single';
            this.activePane = 'left';
            this.tabSequence = 0;
            this.panes = {
                left: { tabs: [], activeTabId: null },
                right: { tabs: [], activeTabId: null },
            };
        }

        assertPane(pane) {
            if (!PANES.has(pane)) {
                throw new TypeError(`Unsupported workspace pane: ${pane}`);
            }
        }

        normalizeSource(source = {}) {
            const normalized = {};
            SOURCE_FIELDS.forEach(field => {
                normalized[field] = source[field] ?? null;
            });
            normalized.capabilities = Array.isArray(normalized.capabilities)
                ? [...normalized.capabilities]
                : [];
            normalized.ephemeral = normalized.ephemeral === true;
            normalized.security = normalized.security
                && typeof normalized.security === 'object'
                ? { ...normalized.security }
                : {};
            return normalized;
        }

        getTabs(pane) {
            this.assertPane(pane);
            return this.panes[pane].tabs;
        }

        getActiveTab(pane) {
            this.assertPane(pane);
            const paneState = this.panes[pane];
            return paneState.tabs.find(tab => tab.id === paneState.activeTabId) || null;
        }

        openTab(pane, source, paneState = this.createPaneState()) {
            this.assertPane(pane);
            const tab = {
                id: `workspace-tab-${++this.tabSequence}`,
                source: this.normalizeSource(source),
                paneState,
            };
            this.panes[pane].tabs.push(tab);
            this.panes[pane].activeTabId = tab.id;
            this.activePane = pane;
            return tab;
        }

        activateTab(pane, tabId) {
            this.assertPane(pane);
            const tab = this.panes[pane].tabs.find(item => item.id === tabId);
            if (!tab) return null;
            this.panes[pane].activeTabId = tab.id;
            this.activePane = pane;
            return tab;
        }

        closeTab(pane, tabId) {
            this.assertPane(pane);
            const paneState = this.panes[pane];
            const index = paneState.tabs.findIndex(tab => tab.id === tabId);
            if (index < 0) return { closed: null, active: this.getActiveTab(pane) };

            const [closed] = paneState.tabs.splice(index, 1);
            if (paneState.activeTabId === tabId) {
                const neighbor = paneState.tabs[index] || paneState.tabs[index - 1] || null;
                paneState.activeTabId = neighbor?.id || null;
            }
            return { closed, active: this.getActiveTab(pane) };
        }

        moveTab(fromPane, toPane, tabId) {
            this.assertPane(fromPane);
            this.assertPane(toPane);
            if (fromPane === toPane) return this.activateTab(fromPane, tabId);

            const result = this.closeTab(fromPane, tabId);
            if (!result.closed) return null;
            this.panes[toPane].tabs.push(result.closed);
            this.panes[toPane].activeTabId = result.closed.id;
            this.activePane = toPane;
            return result.closed;
        }

        setLayout(layout) {
            if (!LAYOUTS.has(layout)) {
                throw new TypeError(`Unsupported workspace layout: ${layout}`);
            }
            this.layout = layout;
            return layout;
        }

        setActivePane(pane) {
            this.assertPane(pane);
            this.activePane = pane;
            return pane;
        }
    }

    globalObject.FileWorkspaceState = FileWorkspaceState;
})(typeof window !== 'undefined' ? window : globalThis);
