/* Preview notice translations, registered before preview-notice.js. */
(() => {
    'use strict';
    const dictionaries = {
        "en": {
            "previewNotice.title": "Preview",
            "previewNotice.text": "This is a preview of the new server. Some features are not available yet.",
            "previewNotice.unavailable": "Not available in this preview yet: {features}",
            "previewNotice.notAvailable": "Not available in this preview yet.",
            "previewNotice.dismiss": "Dismiss preview notice",
            "previewNotice.feature.files": "Files",
            "previewNotice.feature.smb": "SMB shares",
            "previewNotice.feature.commands": "Command library",
            "previewNotice.feature.commandSets": "Command sets",
            "previewNotice.feature.insights": "Session insights",
            "previewNotice.feature.terminalTools": "Terminal tools",
            "previewNotice.feature.other": "Other functions"
        },
        "vi": {
            "previewNotice.title": "Bản xem trước",
            "previewNotice.text": "Đây là bản xem trước của máy chủ mới. Một số tính năng chưa khả dụng.",
            "previewNotice.unavailable": "Chưa khả dụng trong bản xem trước: {features}",
            "previewNotice.notAvailable": "Chưa khả dụng trong bản xem trước này.",
            "previewNotice.dismiss": "Đóng thông báo xem trước",
            "previewNotice.feature.files": "Tệp",
            "previewNotice.feature.smb": "Chia sẻ SMB",
            "previewNotice.feature.commands": "Thư viện lệnh",
            "previewNotice.feature.commandSets": "Bộ lệnh",
            "previewNotice.feature.insights": "Thông tin phiên",
            "previewNotice.feature.terminalTools": "Công cụ terminal",
            "previewNotice.feature.other": "Chức năng khác"
        },
        "de": {
            "previewNotice.title": "Vorschau",
            "previewNotice.text": "Dies ist eine Vorschau des neuen Servers. Einige Funktionen sind noch nicht verfügbar.",
            "previewNotice.unavailable": "In dieser Vorschau noch nicht verfügbar: {features}",
            "previewNotice.notAvailable": "In dieser Vorschau noch nicht verfügbar.",
            "previewNotice.dismiss": "Vorschauhinweis schließen",
            "previewNotice.feature.files": "Dateien",
            "previewNotice.feature.smb": "SMB-Freigaben",
            "previewNotice.feature.commands": "Befehlsbibliothek",
            "previewNotice.feature.commandSets": "Befehlssets",
            "previewNotice.feature.insights": "Sitzungsdetails",
            "previewNotice.feature.terminalTools": "Terminal-Werkzeuge",
            "previewNotice.feature.other": "Weitere Funktionen"
        },
        "fr": {
            "previewNotice.title": "Aperçu",
            "previewNotice.text": "Ceci est un aperçu du nouveau serveur. Certaines fonctions ne sont pas encore disponibles.",
            "previewNotice.unavailable": "Pas encore disponible dans cet aperçu : {features}",
            "previewNotice.notAvailable": "Pas encore disponible dans cet aperçu.",
            "previewNotice.dismiss": "Fermer l’avis d’aperçu",
            "previewNotice.feature.files": "Fichiers",
            "previewNotice.feature.smb": "Partages SMB",
            "previewNotice.feature.commands": "Bibliothèque de commandes",
            "previewNotice.feature.commandSets": "Jeux de commandes",
            "previewNotice.feature.insights": "Détails de session",
            "previewNotice.feature.terminalTools": "Outils du terminal",
            "previewNotice.feature.other": "Autres fonctions"
        },
        "es": {
            "previewNotice.title": "Vista previa",
            "previewNotice.text": "Esta es una vista previa del nuevo servidor. Algunas funciones aún no están disponibles.",
            "previewNotice.unavailable": "Aún no disponible en esta vista previa: {features}",
            "previewNotice.notAvailable": "Aún no disponible en esta vista previa.",
            "previewNotice.dismiss": "Cerrar aviso de vista previa",
            "previewNotice.feature.files": "Archivos",
            "previewNotice.feature.smb": "Recursos SMB",
            "previewNotice.feature.commands": "Biblioteca de comandos",
            "previewNotice.feature.commandSets": "Conjuntos de comandos",
            "previewNotice.feature.insights": "Detalles de sesión",
            "previewNotice.feature.terminalTools": "Herramientas de terminal",
            "previewNotice.feature.other": "Otras funciones"
        },
        "zh": {
            "previewNotice.title": "预览",
            "previewNotice.text": "这是新服务器的预览版。部分功能尚不可用。",
            "previewNotice.unavailable": "此预览版尚不可用：{features}",
            "previewNotice.notAvailable": "此预览版尚不可用。",
            "previewNotice.dismiss": "关闭预览提示",
            "previewNotice.feature.files": "文件",
            "previewNotice.feature.smb": "SMB 共享",
            "previewNotice.feature.commands": "命令库",
            "previewNotice.feature.commandSets": "命令集",
            "previewNotice.feature.insights": "会话详情",
            "previewNotice.feature.terminalTools": "终端工具",
            "previewNotice.feature.other": "其他功能"
        }
    };
    Object.entries(dictionaries).forEach(([language, dictionary]) => window.i18n.addTranslations(language, dictionary));
})();
