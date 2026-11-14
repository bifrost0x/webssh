// Command impact guidance is independent of catalog template mutability.
(function () {
    const bundles = {
    "en": {
        "commandSafety.guidance": "Usage and template details",
        "commandSafety.browse": "Browse",
        "commandSafety.recommended": "Inspection templates + personal",
        "commandSafety.all": "All tasks (includes advanced)",
        "commandSafety.read-only": "Inspects data",
        "commandSafety.changes-system": "Changes system or data",
        "commandSafety.deletes-data": "Deletes or overwrites data",
        "commandSafety.network-load": "Sends network traffic",
        "commandSafety.unknown": "Impact not classified",
        "commandSafety.requires": "Required on target",
        "commandSafety.prerequisites": "Check the installed tool, shell, permissions and arguments before use.",
        "commandSafety.scope": "Impact describes this exact template, not a safety guarantee. Changed arguments, interactive actions and sudo can change the effect."
    },
    "de": {
        "commandSafety.guidance": "Verwendung und Vorlagendetails",
        "commandSafety.browse": "Ansicht",
        "commandSafety.recommended": "Prüfvorlagen + eigene Befehle",
        "commandSafety.all": "Alle Aufgaben (auch erweiterte)",
        "commandSafety.read-only": "Liest Daten",
        "commandSafety.changes-system": "Ändert System oder Daten",
        "commandSafety.deletes-data": "Löscht oder überschreibt Daten",
        "commandSafety.network-load": "Sendet Netzwerkverkehr",
        "commandSafety.unknown": "Wirkung nicht eingestuft",
        "commandSafety.requires": "Auf dem Ziel erforderlich",
        "commandSafety.prerequisites": "Installiertes Werkzeug, Shell, Berechtigungen und Argumente vor Verwendung prüfen.",
        "commandSafety.scope": "Die Wirkung bezieht sich auf diese genaue Vorlage und ist keine Sicherheitsgarantie. Andere Argumente, interaktive Aktionen und sudo können die Wirkung ändern."
    },
    "fr": {
        "commandSafety.guidance": "Utilisation et détails du modèle",
        "commandSafety.browse": "Afficher",
        "commandSafety.recommended": "Modèles de contrôle + personnels",
        "commandSafety.all": "Toutes les tâches (avancées incluses)",
        "commandSafety.read-only": "Consulte les données",
        "commandSafety.changes-system": "Modifie le système ou les données",
        "commandSafety.deletes-data": "Supprime ou écrase des données",
        "commandSafety.network-load": "Émet du trafic réseau",
        "commandSafety.unknown": "Effet non classé",
        "commandSafety.requires": "Requis sur la cible",
        "commandSafety.prerequisites": "Vérifiez l’outil installé, le shell, les droits et les arguments avant utilisation.",
        "commandSafety.scope": "L’effet décrit ce modèle exact, sans garantie de sécurité. D’autres arguments, les actions interactives et sudo peuvent le modifier."
    },
    "es": {
        "commandSafety.guidance": "Uso y detalles de la plantilla",
        "commandSafety.browse": "Ver",
        "commandSafety.recommended": "Plantillas de consulta + personales",
        "commandSafety.all": "Todas las tareas (incluidas avanzadas)",
        "commandSafety.read-only": "Consulta datos",
        "commandSafety.changes-system": "Cambia el sistema o los datos",
        "commandSafety.deletes-data": "Borra o sobrescribe datos",
        "commandSafety.network-load": "Envía tráfico de red",
        "commandSafety.unknown": "Efecto sin clasificar",
        "commandSafety.requires": "Requerido en el destino",
        "commandSafety.prerequisites": "Compruebe la herramienta instalada, el shell, los permisos y los argumentos antes de usar.",
        "commandSafety.scope": "El efecto describe esta plantilla exacta, sin garantizar su seguridad. Otros argumentos, acciones interactivas y sudo pueden cambiarlo."
    },
    "vi": {
        "commandSafety.guidance": "Cách dùng và chi tiết mẫu",
        "commandSafety.browse": "Hiển thị",
        "commandSafety.recommended": "Mẫu kiểm tra + lệnh cá nhân",
        "commandSafety.all": "Tất cả tác vụ (gồm nâng cao)",
        "commandSafety.read-only": "Đọc dữ liệu",
        "commandSafety.changes-system": "Thay đổi hệ thống hoặc dữ liệu",
        "commandSafety.deletes-data": "Xóa hoặc ghi đè dữ liệu",
        "commandSafety.network-load": "Gửi lưu lượng mạng",
        "commandSafety.unknown": "Chưa phân loại tác động",
        "commandSafety.requires": "Cần có trên máy đích",
        "commandSafety.prerequisites": "Kiểm tra công cụ đã cài, shell, quyền và tham số trước khi dùng.",
        "commandSafety.scope": "Tác động mô tả đúng mẫu này, không bảo đảm an toàn. Tham số khác, thao tác tương tác và sudo có thể thay đổi tác động."
    },
    "zh": {
        "commandSafety.guidance": "用法和模板详情",
        "commandSafety.browse": "显示",
        "commandSafety.recommended": "检查模板和个人命令",
        "commandSafety.all": "所有任务（包括高级任务）",
        "commandSafety.read-only": "查看数据",
        "commandSafety.changes-system": "修改系统或数据",
        "commandSafety.deletes-data": "删除或覆盖数据",
        "commandSafety.network-load": "发送网络流量",
        "commandSafety.unknown": "影响未分类",
        "commandSafety.requires": "目标上需要",
        "commandSafety.prerequisites": "使用前请检查已安装的工具、Shell、权限和参数。",
        "commandSafety.scope": "影响说明仅适用于此确切模板，并非安全保证。更改参数、交互操作和 sudo 可能改变其影响。"
    }
};
    for (const [language, values] of Object.entries(bundles)) window.i18n.addTranslations(language, values);
}());
