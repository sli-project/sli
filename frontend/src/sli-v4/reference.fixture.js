(() => {
  'use strict';

  const $ = (selector, root = document) => root.querySelector(selector);
  const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
  const icon = (name) => `<svg class="icon" aria-hidden="true"><use href="#i-${name}"></use></svg>`;

  const reports = {
    'security-queue': {
      id: 'security-queue', title: 'Очередь проблем ИБ', category: 'Безопасность', icon: 'warning', tone: 'warn', route: 'problems',
      description: 'Короткая очередь: что произошло, вероятная причина и безопасное следующее действие.',
      dataset: 'security.problems', owner: 'Отдел ИБ', version: '3.2', sensitivity: 'Служебные данные', tags: ['оператор', 'действия']
    },
    'security-events': {
      id: 'security-events', title: 'События и доказательства', category: 'Безопасность', icon: 'events', tone: 'accent', route: 'events',
      description: 'Точные события, Event ID, источник, UTC, исходные поля и переходы к объектам.',
      dataset: 'evidence.events_v2', owner: 'Отдел ИБ', version: '2.6', sensitivity: 'Технические данные', tags: ['аналитик', 'evidence']
    },
    investigations: {
      id: 'investigations', title: 'Расследования', category: 'Безопасность', icon: 'case', tone: 'purple', route: 'cases',
      description: 'Дела, временные линии, подтверждённые и исключённые доказательства, решения аналитика.',
      dataset: 'cases.workspace', owner: 'Отдел ИБ', version: '2.1', sensitivity: 'Служебные данные', tags: ['дела', 'командная работа']
    },
    'ad-summary': {
      id: 'ad-summary', title: 'Состояние и риски Active Directory', category: 'ИТ и инфраструктура', icon: 'database', tone: 'accent', route: 'ad-report',
      description: 'Сводка домена, DC, Kerberos, LDAP, учётных записей, компьютеров и качества AD.',
      dataset: 'ad.audit.snapshot', owner: 'ИТ-служба', version: '4.0', sensitivity: 'Персональные и технические данные', tags: ['AD', 'аудит']
    },
    'gpo-review': {
      id: 'gpo-review', title: 'GPO — очередь ручной проверки', category: 'ИТ и инфраструктура', icon: 'settings', tone: 'warn', route: 'gpo-report',
      description: 'Приоритеты P1–P4, владельцы, возраст, скрипты, резервная копия и план отката.',
      dataset: 'ad.gpo.governance', owner: 'ИТ-служба', version: '3.4', sensitivity: 'Технические данные', tags: ['GPO', 'governance']
    },
    'privileged-accounts': {
      id: 'privileged-accounts', title: 'Привилегированные учётные записи', category: 'Совместный контроль ИБ и ИТ', icon: 'key', tone: 'bad', route: 'privileged-report',
      description: 'Прямые и вложенные привилегии, активность, парольные исключения и подтверждение владельца.',
      dataset: 'ad.accounts.privileged', owner: 'ИБ + ИТ', version: '2.8', sensitivity: 'Персональные данные', tags: ['привилегии', 'аттестация']
    },
    'vpn-audit': {
      id: 'vpn-audit', title: 'VPN-доступ и актуальность владельцев', category: 'ИТ и инфраструктура', icon: 'lock', tone: 'purple', route: 'vpn-report',
      description: 'Активные, неактивные и привилегированные VPN-пользователи с контекстом учётной записи.',
      dataset: 'ad.access.vpn', owner: 'ИТ-служба', version: '1.9', sensitivity: 'Персональные данные', tags: ['VPN', 'доступ']
    },
    'project-readiness': {
      id: 'project-readiness', title: 'Готовность и устойчивость проекта', category: 'Эксплуатация платформы', icon: 'database', tone: 'good', route: 'project-readiness',
      description: 'Источники, службы, очереди, PostgreSQL, резервные копии, PITR и технические ограничения.',
      dataset: 'platform.readiness', owner: 'Администратор проекта', version: '3.1', sensitivity: 'Внутренние технические данные', tags: ['эксплуатация', 'PITR']
    },
    'technical-events': {
      id: 'technical-events', title: 'Технические события проекта', category: 'Эксплуатация платформы', icon: 'code', tone: 'neutral', route: 'project-readiness',
      description: 'Журнал сбора, обработки, хранения и диагностических проверок платформы.',
      dataset: 'platform.events', owner: 'Администратор проекта', version: '1.7', sensitivity: 'Внутренние технические данные', tags: ['журнал', 'диагностика']
    }
  };

  const accessGroups = {
    'sec-operators': {
      label: 'ИБ · операторы', type: 'Функциональная группа',
      capabilities: ['entity.view', 'entity.basic', 'problem.view', 'problem.act', 'case.create', 'finding.summary'],
      fields: ['identity.basic'], scopes: ['host5.example.invalid'],
      reportGrants: [grant('security-queue', 'Работа', 'host5.example.invalid', 'группа ИБ · операторы')]
    },
    'sec-analysts': {
      label: 'ИБ · аналитики', type: 'Функциональная группа',
      capabilities: ['entity.view', 'entity.basic', 'entity.groups', 'entity.activity', 'entity.states', 'entity.technical', 'event.view', 'evidence.view', 'evidence.raw', 'finding.view', 'case.view', 'case.manage', 'case.create'],
      fields: ['identity.basic', 'technical.raw'], scopes: ['host5.example.invalid'],
      reportGrants: [
        grant('security-events', 'Анализ', 'host5.example.invalid', 'группа ИБ · аналитики'),
        grant('investigations', 'Работа', 'host5.example.invalid', 'группа ИБ · аналитики')
      ]
    },
    'ad-auditors': {
      label: 'AD · аудит и сопровождение', type: 'Функциональная группа',
      capabilities: ['entity.view', 'entity.basic', 'entity.groups', 'entity.privileges', 'entity.states', 'task.create', 'report.export'],
      fields: ['identity.basic', 'pii.contact', 'pii.hr', 'ad.attributes'], scopes: ['host5.example.invalid', 'OU=Users_KHV'],
      reportGrants: [
        grant('ad-summary', 'Анализ', 'host5.example.invalid', 'группа AD · аудит'),
        grant('gpo-review', 'Работа', 'host5.example.invalid', 'группа AD · аудит')
      ]
    },
    'project-ops': {
      label: 'Проект · эксплуатация', type: 'Функциональная группа',
      capabilities: ['project.ops.view', 'project.events.view', 'report.export'],
      fields: ['platform.technical'], scopes: ['platform'],
      reportGrants: [
        grant('project-readiness', 'Эксплуатация', 'platform', 'группа Проект · эксплуатация'),
        grant('technical-events', 'Анализ', 'platform', 'группа Проект · эксплуатация')
      ]
    },
    'access-admins': {
      label: 'Администраторы доступа', type: 'Административная группа',
      capabilities: ['access.manage', 'access.audit', 'report.publish', 'report.design'],
      fields: ['access.metadata'], scopes: ['all-subjects'],
      reportGrants: []
    }
  };

  const users = {
    alex: {
      id: 'alex', name: 'Алексей Кузнецов', short: 'Алексей К.', initials: 'АК', title: 'Специалист ИБ / участник AD-аудита',
      groups: ['sec-operators', 'ad-auditors'],
      directGrants: [directGrant('privileged-accounts', 'Анализ', 'host5.example.invalid', 'Распоряжение ИБ-128', '31.12.2026')],
      pinned: ['security-queue', 'ad-summary', 'privileged-accounts', 'gpo-review'],
      defaultRoute: 'workspace'
    },
    marina: {
      id: 'marina', name: 'Марина Орлова', short: 'Марина О.', initials: 'МО', title: 'Оператор ИБ',
      groups: ['sec-operators'], directGrants: [], pinned: ['security-queue'], defaultRoute: 'workspace'
    },
    dmitry: {
      id: 'dmitry', name: 'Дмитрий Соколов', short: 'Дмитрий С.', initials: 'ДС', title: 'Аналитик ИБ / эксперт AD',
      groups: ['sec-analysts', 'ad-auditors'],
      directGrants: [directGrant('privileged-accounts', 'Анализ', 'host5.example.invalid', 'Проект аттестации PAM-26', '30.09.2026')],
      pinned: ['security-events', 'investigations', 'ad-summary', 'privileged-accounts'], defaultRoute: 'workspace'
    },
    admin: {
      id: 'admin', name: 'Елена Волкова', short: 'Елена В.', initials: 'ЕВ', title: 'Администратор проекта и доступа',
      groups: ['project-ops', 'access-admins'], directGrants: [], pinned: ['project-readiness', 'technical-events'], defaultRoute: 'access-center'
    }
  };

  const demoObjects = [
    { type:'Пользователь AD', icon:'user', initials:'ИИ', title:'Иванов Иван Петрович', id:'CORP\\ivanov', tags:[['Включён','good'],['2 находки','warn']], route:'entity' },
    { type:'Сервисная учётная запись', icon:'key', initials:'SB', title:'svc-backup', id:'CORP\\svc-backup', tags:[['Заблокирована','bad'],['P1','bad']], route:'entity' },
    { type:'Компьютер', icon:'database', initials:'AS', title:'APP-SRV-03', id:'Windows Server 2019', tags:[['Активен','good'],['1 связь','accent']], kind:'computer', route:'entity' },
    { type:'Группа AD', icon:'users', initials:'BO', title:'Backup Operators', id:'CORP\\Backup Operators', tags:[['Привилегированная','bad']], kind:'group', route:'entity' },
    { type:'GPO', icon:'settings', initials:'GP', title:'Workstation Security Baseline', id:'{4A91…E331}', tags:[['P2','warn'],['Нужна проверка','neutral']], kind:'gpo', route:'gpo-report' },
    { type:'Контроллер домена', icon:'database', initials:'D2', title:'DC2', id:'dc2.host5.example.invalid', tags:[['Работает','good'],['Security внутри SLO','good']], kind:'computer', route:'ad-report' },
    { type:'Пользователь AD', icon:'user', initials:'АК', title:'Кузнецов Алексей Сергеевич', id:'CORP\\adm.kuznetsov', tags:[['Привилегированный','bad']], route:'entity' },
    { type:'Группа AD', icon:'users', initials:'VH', title:'VPNl2tp', id:'430 участников', tags:[['Доступ VPN','purple']], kind:'group', route:'vpn-report' }
  ];

  const eventRows = [
    { db:'12854801', eid:'4728', time:'19.07.2026 · 13:37:06', title:'Участник добавлен в привилегированную группу', actor:'CORP\\adm.kuznetsov', target:'CORP\\ivanov', source:'DC2 / Security', risk:'Высокий', tone:'bad' },
    { db:'12853680', eid:'4624', time:'19.07.2026 · 12:48:10', title:'Успешный сетевой вход в систему', actor:'CORP\\ivanov', target:'APP-SRV-03', source:'DC2 / Security', risk:'Низкий', tone:'good' },
    { db:'12853127', eid:'4769', time:'19.07.2026 · 12:21:44', title:'Запрошен сервисный билет Kerberos', actor:'CORP\\ivanov', target:'cifs/files01.host5.example.invalid', source:'DC1 / Security', risk:'Низкий', tone:'neutral' },
    { db:'12849770', eid:'4723', time:'18.07.2026 · 17:26:31', title:'Выполнена попытка смены пароля', actor:'CORP\\ivanov', target:'CORP\\ivanov', source:'DC2 / Security', risk:'Средний', tone:'warn' }
  ];

  const state = {
    userId: safeGet('sli-v4-user') || 'alex',
    route: 'workspace',
    entityTab: 'overview',
    technical: safeGet('sli-v4-technical') === 'true',
    selectedAccessUser: 'alex',
    reportFilter: 'available'
  };
  if (!users[state.userId]) state.userId = 'alex';

  function grant(reportId, level, scope, source) {
    return { reportId, level, scope, source, sourceType:'group', validUntil:'Бессрочно' };
  }
  function directGrant(reportId, level, scope, source, validUntil) {
    return { reportId, level, scope, source, sourceType:'direct', validUntil };
  }
  function safeGet(key) { try { return localStorage.getItem(key); } catch { return null; } }
  function safeSet(key, value) { try { localStorage.setItem(key, value); } catch { /* local file */ } }

  function effectiveAccess(userId = state.userId) {
    const user = users[userId];
    const capabilities = new Set();
    const fields = new Set();
    const scopes = new Set();
    const reportGrants = [];
    user.groups.forEach(groupId => {
      const group = accessGroups[groupId];
      group.capabilities.forEach(v => capabilities.add(v));
      group.fields.forEach(v => fields.add(v));
      group.scopes.forEach(v => scopes.add(v));
      group.reportGrants.forEach(v => reportGrants.push({ ...v, groupId }));
    });
    user.directGrants.forEach(v => reportGrants.push({ ...v }));
    const reportMap = new Map();
    reportGrants.forEach(v => {
      if (!reportMap.has(v.reportId)) reportMap.set(v.reportId, []);
      reportMap.get(v.reportId).push(v);
    });
    return { user, capabilities, fields, scopes, reportGrants, reportMap };
  }

  function can(capability, userId = state.userId) { return effectiveAccess(userId).capabilities.has(capability); }
  function canField(field, userId = state.userId) { return effectiveAccess(userId).fields.has(field); }
  function hasReport(reportId, userId = state.userId) { return effectiveAccess(userId).reportMap.has(reportId); }
  function reportGrant(reportId, userId = state.userId) { return effectiveAccess(userId).reportMap.get(reportId)?.[0] || null; }

  function badge(text, tone = 'neutral', iconName = '') { return `<span class="badge ${tone}">${iconName ? icon(iconName) : ''}${text}</span>`; }
  function status(text, tone = 'neutral') { return `<span class="status ${tone}">${text}</span>`; }
  function button(text, iconName = '', options = {}) {
    const cls = ['button', options.kind || '', options.small ? 'small' : ''].filter(Boolean).join(' ');
    return `<button type="button" class="${cls}" ${options.attrs || ''}>${iconName ? icon(iconName) : ''}${text}</button>`;
  }
  function pageHead({ eyebrow = '', title, subtitle = '', actions = '' }) {
    return `<header class="page-head"><div class="page-head-main">${eyebrow ? `<div class="eyebrow">${eyebrow}</div>` : ''}<h1 class="page-title" data-page-heading tabindex="-1">${title}</h1>${subtitle ? `<p class="page-subtitle">${subtitle}</p>` : ''}</div>${actions ? `<div class="page-actions">${actions}</div>` : ''}</header>`;
  }
  function prototypeBanner() {
    return `<div class="prototype-banner" role="note">${icon('info')}<span><strong>Интерактивный дизайн-прототип.</strong> Данные карточки CORP\\ivanov демонстрационные; числовая структура AD-отчёта основана на предоставленном аудите от 17.07.2026.</span></div>`;
  }
  function metric({ label, value, caption, iconName = 'report', tone = 'accent', badgeHtml = '' }) {
    return `<article class="panel metric ${tone}"><div class="metric-top"><div><div class="metric-label">${label}</div><div class="metric-value">${value}</div></div><div class="metric-icon">${icon(iconName)}</div></div><div class="metric-caption">${caption}</div>${badgeHtml ? `<div style="margin-top:8px">${badgeHtml}</div>` : ''}</article>`;
  }

  function currentUser() { return users[state.userId]; }

  function routeRequirement(route) {
    const reportByRoute = Object.values(reports).find(r => r.route === route);
    if (reportByRoute) return { report: reportByRoute.id };
    const map = {
      workspace: {}, reports: {}, 'access-user': {},
      objects: { capability:'entity.view' }, entity: { capability:'entity.view' },
      problems: { capability:'problem.view' }, events: { capability:'event.view' }, cases: { capability:'case.view' },
      'access-center': { capability:'access.manage' }, 'report-management': { capability:'report.publish' }, 'report-editor': { capability:'report.design' }
    };
    return map[route] || {};
  }

  function routeAllowed(route) {
    const requirement = routeRequirement(route);
    if (requirement.capability && !can(requirement.capability)) return false;
    if (requirement.report && !hasReport(requirement.report)) return false;
    return true;
  }

  function navModel() {
    const groups = [
      { title:'Рабочее пространство', items:[
        ['workspace','Моё рабочее пространство','grid'],
        ['reports','Каталог отчётов','report'],
        ...(can('entity.view') ? [['objects','Объекты и сущности','entity']] : [])
      ]},
      { title:'Работа', items:[
        ...(can('problem.view') ? [['problems','Очередь проблем','warning','3']] : []),
        ...(can('event.view') ? [['events','События','events']] : []),
        ...(can('case.view') ? [['cases','Расследования','case','3']] : [])
      ]},
      { title:'Мои отчёты', items: currentUser().pinned.filter(id => hasReport(id)).map(id => {
        const r = reports[id]; return [r.route, r.title, r.icon, id === 'privileged-accounts' ? 'P1' : ''];
      })},
      ...(can('access.manage') ? [{ title:'Управление', items:[
        ['access-center','Доступы пользователей','users'],
        ['report-management','Публикация отчётов','report'],
        ['report-editor','Конструктор отчёта','edit']
      ]}] : [])
    ];
    return groups.filter(g => g.items.length);
  }

  function renderNav() {
    $('#side-nav').innerHTML = navModel().map(group => `<section class="nav-group"><div class="nav-title">${group.title}</div>${group.items.map(([route,label,iconName,count]) => `<button type="button" class="nav-item ${state.route === route ? 'is-active' : ''}" data-route="${route}">${icon(iconName)}<span class="nav-label">${label}</span>${count ? `<span class="nav-badge">${count}</span>` : ''}</button>`).join('')}</section>`).join('');
  }

  function renderChrome() {
    const access = effectiveAccess();
    const user = access.user;
    $('#demo-user').value = state.userId;
    $('#top-name').textContent = user.short;
    $('#top-avatar').textContent = user.initials;
    $('#top-access').textContent = user.groups.length > 1 ? `${user.groups.length} пакета + ${user.directGrants.length} прямой отчёт` : accessGroups[user.groups[0]].label;
    $('#access-summary').innerHTML = [
      `<span class="mini-chip">${icon('layers')}${user.groups.length} пакета</span>`,
      `<span class="mini-chip">${icon('report')}${access.reportMap.size} отчётов</span>`,
      user.directGrants.length ? `<span class="mini-chip">${icon('key')}${user.directGrants.length} напрямую</span>` : ''
    ].join('');
    $('#sidebar-footer').innerHTML = `<strong>Доступ составной</strong>Меню собирается из прав групп, прямых назначений, области данных и разрешённых полей. Название должности само по себе доступ не выдаёт.`;
    document.body.dataset.technical = String(state.technical);
    const technicalButton = $('#technical-toggle');
    technicalButton.setAttribute('aria-pressed', String(state.technical));
    $('.control-caption', technicalButton).textContent = state.technical ? 'включён' : 'выключен';
  }

  function accessSourceLabel(userId = state.userId) {
    const access = effectiveAccess(userId);
    return access.user.groups.map(id => accessGroups[id].label).join(' + ');
  }

  function reportCard(report, { compact = false } = {}) {
    const grantInfo = reportGrant(report.id);
    const available = Boolean(grantInfo);
    const accessTone = available ? (grantInfo.sourceType === 'direct' ? 'purple' : 'good') : 'neutral';
    const accessText = available ? (grantInfo.sourceType === 'direct' ? `Назначен напрямую до ${grantInfo.validUntil}` : `Доступ через ${grantInfo.source}`) : 'Доступ не назначен';
    const action = available
      ? button(compact ? 'Открыть' : 'Открыть отчёт', 'eye', { kind:'primary', small:compact, attrs:`data-route="${report.route}"` })
      : button('Запросить доступ', 'key', { small:compact, attrs:`data-request-report="${report.id}"` });
    return `<article class="report-card" data-report-access="${available ? 'available' : 'unavailable'}">
      <div class="report-card-top"><div class="report-icon ${report.tone}">${icon(report.icon)}</div>${badge(available ? 'Доступен' : 'По запросу', accessTone)}</div>
      <h3 class="report-title">${report.title}</h3>
      <p class="report-copy">${report.description}</p>
      <div class="report-meta">
        <div class="report-meta-row">${icon('database')}<span>${report.dataset}</span></div>
        <div class="report-meta-row">${icon('users')}<span>${report.owner} · версия ${report.version}</span></div>
        <div class="report-meta-row">${icon('lock')}<span>${report.sensitivity}</span></div>
      </div>
      <div class="report-footer"><span class="cell-secondary">${accessText}</span>${action}</div>
    </article>`;
  }

  function workspacePage() {
    const access = effectiveAccess();
    const user = access.user;
    const groupBadges = user.groups.map(id => badge(accessGroups[id].label, id === 'ad-auditors' ? 'accent' : id === 'sec-operators' ? 'warn' : id === 'sec-analysts' ? 'purple' : 'neutral')).join('');
    const directBadges = user.directGrants.map(g => badge(`${reports[g.reportId].title} · напрямую`, 'purple')).join('');
    const pinned = user.pinned.filter(id => hasReport(id));
    const attention = can('problem.view') ? `
      <div class="card-list">
        <div class="list-item"><div class="risk-marker bad"></div><div class="item-main"><div class="item-title">Проверить включение CORP\\ivanov в Backup Operators</div><div class="item-copy">Прямое изменение подтверждено событием DB 12854801; заявка владельца не связана.</div><div class="item-meta"><span>P1</span><span>22 минуты назад</span><span>Объект: CORP\\ivanov</span></div></div><div class="item-actions">${button('Открыть объект','entity',{small:true,attrs:'data-route="entity" data-entity-tab="overview"'})}</div></div>
        <div class="list-item"><div class="risk-marker warn"></div><div class="item-main"><div class="item-title">Сверить владельцев 8 записей DCSync</div><div class="item-copy">Часть прав может быть штатной; требуется сравнение с разрешённым перечнем.</div><div class="item-meta"><span>P1</span><span>AD-аудит 17.07.2026</span></div></div><div class="item-actions">${button('Открыть AD-отчёт','report',{small:true,attrs:'data-route="ad-report"'})}</div></div>
      </div>` : `<div class="empty-state"><div class="empty-icon">${icon('check')}</div><div class="empty-title">Очередь проблем не входит в текущий доступ</div><div class="empty-copy">Это не означает отсутствие проблем: пользователю просто не назначен соответствующий отчёт.</div></div>`;

    return `${prototypeBanner()}
      ${pageHead({ eyebrow:`${badge('Персональная сборка','accent')} <span>·</span> права объединяются`, title:'Моё рабочее пространство', subtitle:'Один пользователь может одновременно работать как оператор ИБ, участник AD-аудита и читатель отдельного отчёта. Навигация и карточки собираются из эффективного доступа.' })}
      <section class="workspace-hero">
        <div class="hero-panel">
          <div class="eyebrow">Текущий пользователь</div>
          <h2 class="hero-title">${user.name}</h2>
          <p class="hero-copy">${user.title}. Интерфейс не заставляет выбирать одну роль: доступ складывается из ${user.groups.length} пакетов, ${user.directGrants.length} прямых назначений, области данных и разрешённых категорий полей.</p>
          <div class="hero-access">${groupBadges}${directBadges || badge('Прямых назначений нет','neutral')}</div>
          <div class="hero-actions">${button('Посмотреть эффективный доступ','key',{kind:'primary',attrs:'data-route="access-user"'})}${button('Открыть каталог отчётов','report',{attrs:'data-route="reports"'})}</div>
        </div>
        <aside class="panel pad section-stack">
          <div><div class="eyebrow">Как собран экран</div><h2 class="panel-title">Не «одна роль», а четыре слоя</h2></div>
          <div class="detail-list">
            <div class="detail-row"><dt>Пользователь и группы</dt><dd>${user.groups.length} пакета доступа</dd></div>
            <div class="detail-row"><dt>Отчёты</dt><dd>${access.reportMap.size} разрешено</dd></div>
            <div class="detail-row"><dt>Область данных</dt><dd>${[...access.scopes].join(', ')}</dd></div>
            <div class="detail-row"><dt>Поля и действия</dt><dd>${access.fields.size} категорий · ${access.capabilities.size} возможностей</dd></div>
          </div>
          <div class="callout good">${icon('check')}<div><div class="callout-title">Совмещение поддерживается</div><div class="callout-copy">Добавление нового отчёта не требует создавать ещё одну профессию или копировать весь интерфейс.</div></div></div>
        </aside>
      </section>

      <section class="grid four" style="margin-bottom:14px">
        ${metric({label:'Доступные отчёты',value:String(access.reportMap.size),caption:'из каталога проекта',iconName:'report',tone:'accent'})}
        ${metric({label:'Требует внимания',value:can('problem.view') ? '3' : '—',caption:can('problem.view') ? 'проблемы в очереди ИБ' : 'отчёт не назначен',iconName:'warning',tone:can('problem.view') ? 'bad' : 'accent'})}
        ${metric({label:'Объекты в области',value:can('entity.view') ? '4 821' : '—',caption:can('entity.view') ? 'пользователи, группы, компьютеры, GPO' : 'нет права entity.view',iconName:'entity',tone:'good'})}
        ${metric({label:'Прямые назначения',value:String(user.directGrants.length),caption:user.directGrants.length ? 'с ограниченным сроком' : 'все доступы получены через группы',iconName:'key',tone:'warn'})}
      </section>

      <div class="grid main-aside">
        <section class="section-stack">
          <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Закреплённые отчёты</h2><p class="panel-subtitle">Пользователь может собрать свой рабочий экран из разрешённых модулей.</p></div>${button('Настроить','settings',{small:true,attrs:'data-route="reports"'})}</div><div class="panel-body"><div class="report-grid">${pinned.map(id => reportCard(reports[id],{compact:true})).join('')}</div></div></section>
          <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Что требует решения</h2><p class="panel-subtitle">Содержимое появляется только из назначенных отчётов и разрешённой области данных.</p></div>${badge(can('problem.view') ? '2 показано' : 'нет доступа', can('problem.view') ? 'bad' : 'neutral')}</div><div class="panel-body">${attention}</div></section>
        </section>
        <aside class="section-stack">
          ${can('entity.view') ? `<section class="panel"><div class="panel-head"><div><h2 class="panel-title">Недавние объекты</h2><p class="panel-subtitle">Переход в единую карточку.</p></div></div><div class="panel-body card-list">${demoObjects.slice(0,4).map(objectListItem).join('')}</div></section>` : ''}
          <section class="callout purple">${icon('info')}<div><div class="callout-title">Администратор не назначает «главную роль»</div><div class="callout-copy">Он выдаёт пакеты возможностей, конкретные отчёты, область данных, доступ к чувствительным полям и действиям. Итог можно предварительно посмотреть от имени пользователя.</div></div></section>
        </aside>
      </div>`;
  }

  function objectListItem(item) {
    return `<div class="list-item"><div class="object-avatar ${item.kind || ''}">${item.initials}</div><div class="item-main"><div class="item-title"><button class="link-button" data-route="${item.route}" ${item.route === 'entity' ? 'data-entity-tab="overview"' : ''}>${item.title}</button></div><div class="item-copy">${item.type} · ${item.id}</div><div class="cell-tags">${item.tags.map(([t,tone]) => badge(t,tone)).join('')}</div></div>${icon('chevron')}</div>`;
  }

  function reportsPage() {
    const all = Object.values(reports);
    const visible = state.reportFilter === 'available' ? all.filter(r => hasReport(r.id)) : state.reportFilter === 'request' ? all.filter(r => !hasReport(r.id)) : all;
    return `${prototypeBanner()}
      ${pageHead({ eyebrow:`${badge('Каталог','accent')} <span>·</span> отчёты не равны ролям`, title:'Каталог отчётов', subtitle:'Каждый отчёт публикуется отдельно и может быть назначен пользователю или группе. Доступ к самому отчёту не отменяет проверку области данных, полей и разрешённых действий.', actions:can('report.publish') ? button('Управлять публикацией','settings',{kind:'primary',attrs:'data-route="report-management"'}) : button('Мой доступ','key',{attrs:'data-route="access-user"'}) })}
      <section class="toolbar"><div class="field grow"><label>Поиск по каталогу</label><div class="input-wrap">${icon('search')}<input id="report-search" placeholder="AD, GPO, события, VPN…"></div></div><div class="field"><label>Показывать</label><select id="report-filter"><option value="available" ${state.reportFilter==='available'?'selected':''}>Доступные мне</option><option value="all" ${state.reportFilter==='all'?'selected':''}>Весь каталог</option><option value="request" ${state.reportFilter==='request'?'selected':''}>Можно запросить</option></select></div></section>
      <section class="callout">${icon('lock')}<div><div class="callout-title">Три независимые проверки</div><div class="callout-copy">1) разрешён ли отчёт; 2) входит ли объект в область данных пользователя; 3) разрешены ли конкретные поля и действия. Скрытие пункта меню не является механизмом защиты.</div></div></section>
      <div class="report-grid" id="report-grid" style="margin-top:14px">${visible.map(r => reportCard(r)).join('')}</div>`;
  }

  function objectsPage() {
    return `${prototypeBanner()}
      ${pageHead({ eyebrow:`${badge('Единый реестр','accent')} <span>·</span> логи + состояние`, title:'Объекты и сущности', subtitle:'Поиск работает по пользователям, учётным записям, компьютерам, группам, DC, GPO и другим зарегистрированным типам. Каждый результат открывается в одном базовом шаблоне карточки.' })}
      <section class="toolbar"><div class="field grow"><label>Поиск объекта</label><div class="input-wrap">${icon('search')}<input value="ivanov" placeholder="Логин, ФИО, email, SID, hostname или GUID"></div></div><div class="field"><label>Тип</label><select><option>Все типы</option><option>Пользователь AD</option><option>Компьютер</option><option>Группа</option><option>GPO</option></select></div><div class="field"><label>Источник</label><select><option>Все доступные</option><option>AD snapshot</option><option>Windows Event Log</option><option>HR</option></select></div>${button('Найти','search',{kind:'primary',attrs:'data-toast-title="Поиск выполнен" data-toast-copy="Показаны результаты только из разрешённой области данных."'})}</section>
      <section class="grid four" style="margin-bottom:14px">
        ${metric({label:'Пользователи и УЗ',value:'3 014',caption:'наблюдаются в AD snapshot',iconName:'user',tone:'accent'})}
        ${metric({label:'Компьютеры',value:'187',caption:'включая 2 DC',iconName:'database',tone:'good'})}
        ${metric({label:'Группы',value:'1 204',caption:'прямые и вложенные связи',iconName:'users',tone:'warn'})}
        ${metric({label:'Типы объектов',value:'8',caption:'карточка расширяется плагинами',iconName:'layers',tone:'accent'})}
      </section>
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Результаты</h2><p class="panel-subtitle">В карточке видно происхождение и время каждого значения.</p></div>${badge('8 объектов','outline')}</div><div class="panel-body"><div class="object-search-grid">${demoObjects.map(objectCard).join('')}</div></div></section>`;
  }

  function objectCard(item) {
    return `<article class="object-card" data-route="${item.route}" ${item.route === 'entity' ? 'data-entity-tab="overview"' : ''}><div class="object-avatar ${item.kind || ''}">${item.initials}</div><div class="object-main"><div class="eyebrow" style="margin:0 0 2px">${item.type}</div><div class="object-title">${item.title}</div><div class="object-id">${item.id}</div><div class="object-tags">${item.tags.map(([t,tone]) => badge(t,tone)).join('')}</div></div></article>`;
  }

  function entityTabs() {
    const tabs = [
      ['overview','Обзор','user',''],
      ...(can('entity.groups') ? [['groups','Членство в группах','users','6']] : []),
      ...(can('entity.privileges') ? [['privileges','Доступ и привилегии','key','3']] : []),
      ...(can('entity.activity') ? [['activity','Активность','history','4']] : []),
      ...(can('entity.states') ? [['states','Состояние и изменения','layers','5']] : []),
      ...(can('finding.view') || can('finding.summary') ? [['findings','Находки','warning','2']] : []),
      ...(can('evidence.view') ? [['evidence','Доказательства','events','4']] : []),
      ...(can('entity.technical') ? [['technical','Технические данные','code','']] : [])
    ];
    if (!tabs.some(t => t[0] === state.entityTab)) state.entityTab = 'overview';
    return tabs;
  }

  function entityPage() {
    const tabs = entityTabs();
    const hiddenTabs = [
      !can('entity.groups') ? 'членство в группах' : '',
      !can('entity.privileges') ? 'эффективные привилегии' : '',
      !can('evidence.view') ? 'точные доказательства' : '',
      !can('entity.technical') ? 'технические атрибуты' : ''
    ].filter(Boolean);
    return `${prototypeBanner()}
      <header class="entity-header">
        <div class="entity-identity">
          <div class="entity-photo">ИИ</div>
          <div class="entity-heading">
            <div class="entity-type">${badge('Пользователь AD','accent','user')}${status('Включён','good')}${badge('2 находки','warn')}${badge('Данные частично расходятся','purple')}</div>
            <h1 class="entity-name" data-page-heading tabindex="-1">Иванов Иван Петрович</h1>
            <div class="entity-login"><span class="mono">CORP\\ivanov</span> · <span>ivanov@host5.example.invalid</span> · объект <span class="mono">ent_01J4F7M2YV</span></div>
          </div>
          <div class="entity-quick">
            ${can('task.create') ? button('Создать задачу','case',{kind:'primary',attrs:'data-toast-title="Задача создана" data-toast-copy="Объект, находка и область данных добавлены в черновик задачи."'}) : ''}
            ${can('case.create') ? button('Начать расследование','branch',{attrs:'data-toast-title="Расследование создано" data-toast-copy="CORP\\ivanov добавлен как исходный объект; доказательства не подменяются профилем."'}) : ''}
            ${button('Скопировать ссылку','copy',{attrs:'data-copy="https://host20.example.invalid/app/objects/ent_01J4F7M2YV"'})}
          </div>
        </div>
        <div class="entity-freshness">
          <div class="freshness-item"><div class="freshness-label">AD snapshot</div><div class="freshness-value">19.07.2026 14:02 · 8 минут назад</div></div>
          <div class="freshness-item"><div class="freshness-label">События Security</div><div class="freshness-value">19.07.2026 14:08 · 2 минуты назад</div></div>
          <div class="freshness-item"><div class="freshness-label">HR-каталог</div><div class="freshness-value">19.07.2026 06:00 · 8 часов назад</div></div>
          <div class="freshness-item"><div class="freshness-label">Область доступа</div><div class="freshness-value">host5.example.invalid · OU=Users_KHV</div></div>
        </div>
        <div class="tabs" role="tablist">${tabs.map(([id,label,iconName,count]) => `<button type="button" class="tab ${state.entityTab === id ? 'is-active' : ''}" role="tab" aria-selected="${state.entityTab === id}" data-entity-tab="${id}">${icon(iconName)}${label}${count ? `<span class="tab-count">${count}</span>` : ''}</button>`).join('')}</div>
      </header>
      ${hiddenTabs.length ? `<div class="callout" style="margin-bottom:14px">${icon('lock')}<div><div class="callout-title">Состав карточки зависит от доступа</div><div class="callout-copy">Текущему пользователю не показаны: ${hiddenTabs.join(', ')}. Эти разделы можно выдать отдельно без смены основной роли.</div></div></div>` : ''}
      <div class="entity-tab-body">${renderEntityTab()}</div>`;
  }

  function renderEntityTab() {
    const renderers = {
      overview: entityOverview,
      groups: entityGroups,
      privileges: entityPrivileges,
      activity: entityActivity,
      states: entityStates,
      findings: entityFindings,
      evidence: entityEvidence,
      technical: entityTechnical
    };
    return (renderers[state.entityTab] || entityOverview)();
  }

  function sourceMeta(source, observed, kind = '') {
    return `<div class="field-source"><span class="source-dot ${kind}"></span>${source} · ${observed}</div>`;
  }

  function identityField(name, value, source, observed, options = {}) {
    const allowed = !options.permission || canField(options.permission);
    const displayed = allowed ? value : '••••••••';
    const sourceHtml = allowed ? sourceMeta(source, observed, options.sourceKind || '') : `<div class="field-source">${icon('lock')} поле скрыто политикой доступа</div>`;
    return `<div class="identity-field"><div class="field-name">${name}</div><div class="field-value ${allowed ? '' : 'masked'}">${displayed}</div>${sourceHtml}</div>`;
  }

  function entityOverview() {
    return `<div class="grid entity-layout">
      <section class="section-stack">
        <section class="callout purple">${icon('link')}<div><div class="callout-title">Единая карточка не означает слияние разных объектов</div><div class="callout-copy">Внутри связаны «сотрудник Иванов И. П.» и «учётная запись CORP\\ivanov». Источники, время наблюдения и конфликты атрибутов сохраняются отдельно — это защищает от ошибочного объединения людей и логинов.</div></div></section>
        <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Профиль и контактные данные</h2><p class="panel-subtitle">У каждого значения видны источник и актуальность.</p></div>${badge('8 полей','outline')}</div><div class="identity-grid">
          ${identityField('Полное ФИО','Иванов Иван Петрович','AD','14:02')}
          ${identityField('Должность','Старший специалист технической поддержки','HR','06:00',{permission:'pii.hr',sourceKind:'hr'})}
          ${identityField('Отдел','Служба по информационным технологиям','AD + HR','14:02 / 06:00',{permission:'pii.hr',sourceKind:'hr'})}
          ${identityField('Руководитель','Петрова Анна Сергеевна','HR','06:00',{permission:'pii.hr',sourceKind:'hr'})}
          ${identityField('Рабочая почта','i.ivanov@corp.example.test','AD','14:02',{permission:'pii.contact'})}
          ${identityField('Телефон','+7 (3843) 55-21-18, доб. 418','HR','06:00',{permission:'pii.contact',sourceKind:'hr'})}
          ${identityField('Расположение','Новокузнецк · Офис 2 · 3 этаж','AD','14:02')}
          ${identityField('Табельный номер','004182','HR','06:00',{permission:'pii.hr',sourceKind:'hr'})}
        </div></section>
        <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Учётная запись AD</h2><p class="panel-subtitle">Текущее наблюдаемое состояние, а не обещание состояния «прямо сейчас».</p></div>${status('Снимок 8 минут назад','good')}</div><div class="identity-grid">
          ${identityField('Логин','CORP\\ivanov','AD','14:02')}
          ${identityField('UPN','ivanov@host5.example.invalid','AD','14:02')}
          ${identityField('Статус','Включена, не заблокирована','AD','14:02')}
          ${identityField('Последний вход','19.07.2026 12:48','AD + Security','14:02 / 12:48')}
          ${identityField('Пароль изменён','17.02.2026 · 153 дня назад','AD','14:02')}
          ${identityField('Срок действия','Не ограничен','AD','14:02')}
          ${identityField('Создана','12.09.2019','AD','14:02')}
          ${identityField('OU','OU=Новокузнецк,OU=Users_KHV','AD','14:02')}
        </div></section>
      </section>
      <aside class="section-stack">
        <section class="panel pad"><div class="eyebrow">Краткая оценка</div><h2 class="panel-title">Что важно сейчас</h2><div class="risk-stack" style="margin-top:12px">
          <div class="risk-row"><div class="risk-marker bad"></div><div class="risk-content"><div class="risk-title">Вложенная привилегия Backup Operators</div><div class="risk-copy">Путь проходит через группу IT-Helpdesk. Владелец доступа не подтверждён.</div></div><div class="risk-side">${badge('P1','bad')}</div></div>
          <div class="risk-row"><div class="risk-marker warn"></div><div class="risk-content"><div class="risk-title">Пароль старше порога</div><div class="risk-copy">153 дня при политике контроля 120 дней.</div></div><div class="risk-side">${badge('P2','warn')}</div></div>
          <div class="risk-row"><div class="risk-marker good"></div><div class="risk-content"><div class="risk-title">Учётная запись активна</div><div class="risk-copy">Последний вход наблюдался сегодня; блокировка не зафиксирована.</div></div><div class="risk-side">${badge('наблюдение','good')}</div></div>
        </div></section>
        <section class="panel pad"><div class="eyebrow">Связанные объекты</div><h2 class="panel-title">Контекст на одной карточке</h2><div class="card-list" style="margin-top:12px">
          ${objectListItem({type:'Персона',initials:'ИИ',title:'Иванов Иван Петрович',id:'HR person · 004182',tags:[['связан','accent']],route:'entity'})}
          ${objectListItem({type:'Компьютер',initials:'WS',title:'WS-NVKZ-0418',id:'последняя рабочая станция',tags:[['15 минут назад','good']],kind:'computer',route:'entity'})}
          ${objectListItem({type:'Группа AD',initials:'IH',title:'IT-Helpdesk',id:'прямое членство',tags:[['3 вложенных пути','purple']],kind:'group',route:'entity'})}
        </div></section>
        <section class="callout warn">${icon('warning')}<div><div class="callout-title">Конфликт данных</div><div class="callout-copy">В HR должность обновлена 19.07, а AD-атрибут title всё ещё содержит «Специалист поддержки». Карточка показывает оба источника и не выбирает удобное значение молча.</div></div></section>
      </aside>
    </div>`;
  }

  function entityGroups() {
    const evidenceAllowed = can('evidence.view');
    return `<div class="grid entity-layout">
      <section class="section-stack">
        <section class="panel pad"><div class="eyebrow">Критический путь</div><h2 class="panel-title">Как пользователь получил привилегию</h2><p class="panel-subtitle">Прямое и вложенное членство визуально различаются.</p><div class="group-path" style="margin-top:13px"><span class="path-node">CORP\\ivanov</span><span class="path-arrow">→ прямое членство →</span><span class="path-node">IT-Helpdesk</span><span class="path-arrow">→ вложено →</span><span class="path-node danger">Backup Operators</span></div><div class="item-meta"><span>Источник связи: AD snapshot 19.07.2026 14:02</span><span>${evidenceAllowed ? 'Изменение: event DB 12854801' : 'Точное событие скрыто текущим доступом'}</span></div></section>
        <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Членство в группах</h2><p class="panel-subtitle">6 эффективных групп: 3 прямых и 3 вложенных.</p></div>${button('Выгрузить CSV','download',{small:true,attrs:can('report.export')?'data-toast-title="Экспорт подготовлен" data-toast-copy="Экспорт содержит только разрешённые поля и область host5.example.invalid."':'data-request-capability="report.export"'})}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Группа</th><th>Тип связи</th><th>Назначение</th><th>Влияние</th><th>Источник / наблюдение</th><th>Действие</th></tr></thead><tbody>
          <tr><td><div class="cell-primary">IT-Helpdesk</div><div class="cell-secondary mono">CN=IT-Helpdesk,OU=Groups</div></td><td>${badge('Прямое','accent')}</td><td>Рабочая группа поддержки</td><td>${status('Обычный доступ','neutral')}</td><td>AD snapshot · 14:02</td><td>${button('Открыть группу','eye',{small:true,attrs:'data-toast-title="Карточка группы" data-toast-copy="В универсальной карточке группы будут участники, вложенность, владельцы, события и находки."'})}</td></tr>
          <tr><td><div class="cell-primary">VPNl2tp</div><div class="cell-secondary mono">CN=VPNl2tp,OU=Access</div></td><td>${badge('Прямое','accent')}</td><td>Удалённый доступ</td><td>${status('VPN разрешён','purple')}</td><td>AD snapshot · 14:02</td><td>${button('Открыть отчёт','report',{small:true,attrs:hasReport('vpn-audit')?'data-route="vpn-report"':'data-request-report="vpn-audit"'})}</td></tr>
          <tr><td><div class="cell-primary">Corp-Employees</div></td><td>${badge('Прямое','accent')}</td><td>Базовый доступ сотрудника</td><td>${status('Базовый','good')}</td><td>AD snapshot · 14:02</td><td>—</td></tr>
          <tr><td><div class="cell-primary">Backup Operators</div><div class="cell-secondary">через IT-Helpdesk</div></td><td>${badge('Вложенное','purple')}</td><td>Операции резервного копирования</td><td>${status('Привилегия P1','bad')}</td><td>${evidenceAllowed ? '<span class="mono">DB 12854801</span>' : 'AD snapshot · событие ограничено'}</td><td>${can('task.create') ? button('Создать проверку','case',{small:true,attrs:'data-toast-title="Проверка создана" data-toast-copy="Добавлены путь членства и требование подтвердить владельца."'}) : button('Запросить действие','key',{small:true,attrs:'data-request-capability="task.create"'})}</td></tr>
          <tr><td><div class="cell-primary">Remote Management Users</div><div class="cell-secondary">через IT-Helpdesk</div></td><td>${badge('Вложенное','purple')}</td><td>Удалённое управление</td><td>${status('Расширенный','warn')}</td><td>AD snapshot · 14:02</td><td>—</td></tr>
          <tr><td><div class="cell-primary">Domain Users</div></td><td>${badge('Вложенное','neutral')}</td><td>Первичная группа</td><td>${status('Базовый','good')}</td><td>AD snapshot · 14:02</td><td>—</td></tr>
        </tbody></table></div></section>
      </section>
      <aside class="section-stack">
        <section class="panel pad"><div class="eyebrow">Фильтр карточки</div><h2 class="panel-title">Что считать важным</h2><div class="detail-list" style="margin-top:8px"><div class="detail-row"><dt>Прямые группы</dt><dd>3</dd></div><div class="detail-row"><dt>Вложенные группы</dt><dd>3</dd></div><div class="detail-row"><dt>Привилегированные пути</dt><dd class="text-bad">1</dd></div><div class="detail-row"><dt>Группы без владельца</dt><dd class="text-warn">1</dd></div></div></section>
        <section class="callout">${icon('info')}<div><div class="callout-title">Нужна история отношений</div><div class="callout-copy">Для каждой связи следует хранить first seen, last seen, direct/inherited, путь, источник, точное evidence и время прекращения членства. Это позволит отличать текущий снимок от произошедшего изменения.</div></div></section>
      </aside>
    </div>`;
  }

  function entityPrivileges() {
    return `<div class="grid entity-layout">
      <section class="section-stack">
        <section class="grid three">
          ${metric({label:'Эффективные привилегии',value:'3',caption:'1 требует срочной проверки',iconName:'key',tone:'bad',badgeHtml:badge('1 путь P1','bad')})}
          ${metric({label:'Удалённый доступ',value:'VPN + RDP',caption:'через две разные группы',iconName:'lock',tone:'warn'})}
          ${metric({label:'Назначенные GPO',value:'7',caption:'2 влияют на ограничения входа',iconName:'settings',tone:'accent'})}
        </section>
        <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Эффективный доступ</h2><p class="panel-subtitle">Результат вычисляется из прямых и вложенных связей, но каждая строка сохраняет путь происхождения.</p></div>${badge('на 14:02','outline')}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Доступ</th><th>Получен через</th><th>Область</th><th>Оценка</th><th>Основание</th></tr></thead><tbody>
          <tr><td><div class="cell-primary">Backup Operators</div><div class="cell-secondary">Операции резервного копирования на контроллерах</div></td><td>IT-Helpdesk → Backup Operators</td><td>host5.example.invalid</td><td>${status('P1 · проверить','bad')}</td><td>Владелец не подтверждён</td></tr>
          <tr><td><div class="cell-primary">VPN L2TP</div><div class="cell-secondary">Удалённое подключение</div></td><td>VPNl2tp</td><td>Периметр компании</td><td>${status('Допустимо','good')}</td><td>Заявка SD-24118 · до 31.12.2026</td></tr>
          <tr><td><div class="cell-primary">Remote Management</div><div class="cell-secondary">WinRM/RDP для серверов поддержки</div></td><td>IT-Helpdesk → Remote Management Users</td><td>OU=Support-Servers</td><td>${status('Нужно подтвердить','warn')}</td><td>Нет срока пересмотра</td></tr>
        </tbody></table></div></section>
        <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Политики и ограничения</h2><p class="panel-subtitle">Не только «есть доступ», но и какие политики его формируют.</p></div></div><div class="table-wrap"><table class="data-table"><thead><tr><th>Объект</th><th>Связь</th><th>Что задаёт</th><th>Источник</th><th>Состояние</th></tr></thead><tbody>
          <tr><td><button class="link-button" data-route="gpo-report">Workstation Security Baseline</button></td><td>GPO применена к OU</td><td>Ограничения входа и аудит</td><td>AD snapshot · 14:02</td><td>${status('Применяется','good')}</td></tr>
          <tr><td><button class="link-button" data-route="gpo-report">Helpdesk Remote Access</button></td><td>GPO через группу</td><td>Remote Desktop / WinRM</td><td>AD + SYSVOL · 13:54</td><td>${status('Нужна проверка','warn')}</td></tr>
          <tr><td>ACL: OU=Support-Servers</td><td>Делегирование группе</td><td>Сброс пароля компьютеров</td><td>AD snapshot · 14:02</td><td>${status('Штатно','neutral')}</td></tr>
        </tbody></table></div></section>
      </section>
      <aside class="section-stack">
        <section class="callout bad">${icon('warning')}<div><div class="callout-title">Привилегия не равна нарушению</div><div class="callout-copy">Карточка показывает риск пути и отсутствие подтверждённого владельца. Она не называет пользователя нарушителем до проверки основания.</div></div></section>
        <section class="panel pad"><div class="eyebrow">Предлагаемые действия</div><h2 class="panel-title">Без прямого изменения AD</h2><div class="card-list" style="margin-top:12px">
          <div class="list-item"><div class="item-main"><div class="item-title">Запросить владельца доступа</div><div class="item-copy">Отправить задачу ответственному за IT-Helpdesk.</div></div>${can('task.create') ? button('Создать','plus',{small:true,attrs:'data-toast-title="Запрос создан" data-toast-copy="Указаны пользователь, путь привилегии и срок ответа."'}) : badge('нет права','neutral')}</div>
          <div class="list-item"><div class="item-main"><div class="item-title">Добавить в расследование</div><div class="item-copy">Сохранить объект, путь и связанные события.</div></div>${can('case.create') ? button('Добавить','case',{small:true,attrs:'data-toast-title="Добавлено в дело" data-toast-copy="Связь сохранена вместе с источником и временем наблюдения."'}) : badge('нет права','neutral')}</div>
        </div></section>
      </aside>
    </div>`;
  }

  function entityActivity() {
    const evidenceAllowed = can('evidence.view');
    return `<div class="grid entity-layout">
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Активность объекта</h2><p class="panel-subtitle">События и изменения состояния объединены в одну временную линию, но тип источника всегда обозначен.</p></div>${badge('последние 24 часа','outline')}</div><div class="panel-body"><div class="timeline">
        <div class="timeline-row"><div class="timeline-time">13:37</div><div class="timeline-rail"><div class="timeline-dot bad"></div></div><div class="timeline-content"><div class="timeline-title">Добавлен в группу Backup Operators</div><div class="timeline-copy">Действие выполнил CORP\\adm.kuznetsov. Причина изменения не содержится в событии.</div><div class="timeline-meta"><span>Security · Event ID 4728</span><span>${evidenceAllowed ? 'DB 12854801' : 'точный ID доступен аналитикам'}</span><span>DC2</span></div></div></div>
        <div class="timeline-row"><div class="timeline-time">12:48</div><div class="timeline-rail"><div class="timeline-dot"></div></div><div class="timeline-content"><div class="timeline-title">Успешный сетевой вход</div><div class="timeline-copy">Целевой компьютер APP-SRV-03, тип входа 3. Событие подтверждает вход, но не физическое присутствие пользователя.</div><div class="timeline-meta"><span>Security · Event ID 4624</span><span>${evidenceAllowed ? 'DB 12853680' : 'точный ID ограничен'}</span><span>DC2</span></div></div></div>
        <div class="timeline-row"><div class="timeline-time">12:21</div><div class="timeline-rail"><div class="timeline-dot"></div></div><div class="timeline-content"><div class="timeline-title">Запрошен билет Kerberos для файлового сервиса</div><div class="timeline-copy">SPN cifs/files01.host5.example.invalid.</div><div class="timeline-meta"><span>Security · Event ID 4769</span><span>${evidenceAllowed ? 'DB 12853127' : 'точный ID ограничен'}</span><span>DC1</span></div></div></div>
        <div class="timeline-row"><div class="timeline-time">06:00</div><div class="timeline-rail"><div class="timeline-dot warn"></div></div><div class="timeline-content"><div class="timeline-title">HR изменил должность</div><div class="timeline-copy">«Специалист поддержки» → «Старший специалист технической поддержки». AD-атрибут title ещё не синхронизирован.</div><div class="timeline-meta"><span>HR snapshot</span><span>изменение атрибута</span></div></div></div>
      </div></div></section>
      <aside class="section-stack">
        <section class="panel pad"><div class="eyebrow">Границы линии</div><h2 class="panel-title">Покрытие источников</h2><div class="detail-list" style="margin-top:8px"><div class="detail-row"><dt>DC2 Security</dt><dd class="text-good">Актуален</dd></div><div class="detail-row"><dt>DC1 Security</dt><dd class="text-warn">Догоняет backlog</dd></div><div class="detail-row"><dt>AD snapshot</dt><dd class="text-good">8 минут</dd></div><div class="detail-row"><dt>HR</dt><dd>8 часов</dd></div></div></section>
        <section class="callout warn">${icon('warning')}<div><div class="callout-title">Линия может дополниться</div><div class="callout-copy">DC1 продолжает ограниченное догоняющее чтение. Отсутствие события на линии сейчас не доказывает, что действие не происходило.</div></div></section>
      </aside>
    </div>`;
  }

  function entityStates() {
    return `<div class="section-stack">
      <section class="callout">${icon('info')}<div><div class="callout-title">Состояние всегда привязано ко времени наблюдения</div><div class="callout-copy">«Включена» означает, что такой атрибут наблюдался в AD snapshot 19.07.2026 14:02. Карточка не выдаёт снимок за непрерывную гарантию текущего состояния.</div></div></section>
      <section class="state-grid">
        <article class="state-card"><div class="state-label">account.enabled</div><div class="state-value text-good">Включена</div><div class="state-copy">AD snapshot · 14:02 · правило ad-user-state v3</div></article>
        <article class="state-card"><div class="state-label">account.access</div><div class="state-value text-good">Не заблокирована</div><div class="state-copy">AD snapshot · 14:02 · lockoutTime=0</div></article>
        <article class="state-card"><div class="state-label">password.age</div><div class="state-value text-warn">153 дня</div><div class="state-copy">Порог контроля: 120 дней</div></article>
        <article class="state-card"><div class="state-label">identity.department</div><div class="state-value">ИТ-служба</div><div class="state-copy">AD + HR · значения совпадают</div></article>
        <article class="state-card"><div class="state-label">identity.title</div><div class="state-value" style="color:var(--purple)">Конфликт</div><div class="state-copy">HR новее AD; автоматический выбор запрещён</div></article>
        <article class="state-card"><div class="state-label">activity.last_logon</div><div class="state-value">Сегодня 12:48</div><div class="state-copy">AD lastLogonTimestamp + событие 4624</div></article>
      </section>
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">История изменений состояний</h2><p class="panel-subtitle">Не только текущее значение, но и когда оно изменилось, каким правилом и на основании чего.</p></div>${badge('5 записей','outline')}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Время</th><th>Тип состояния</th><th>Было</th><th>Стало</th><th>Источник</th><th>Подтверждение</th></tr></thead><tbody>
        <tr><td>19.07.2026 14:02</td><td>identity.title</td><td>Специалист поддержки</td><td>${badge('Конфликт источников','purple')}</td><td>AD + HR</td><td>snapshot hashes сохранены</td></tr>
        <tr><td>19.07.2026 13:37</td><td>access.privileged</td><td>Нет</td><td class="text-bad">Backup Operators</td><td>Security event + AD</td><td>${can('evidence.view') ? '<span class="mono">DB 12854801</span>' : 'evidence ограничено'}</td></tr>
        <tr><td>18.07.2026 17:26</td><td>password.changed</td><td>17.02.2026</td><td>Попытка изменения</td><td>Security event</td><td>${can('evidence.view') ? '<span class="mono">DB 12849770</span>' : 'evidence ограничено'}</td></tr>
        <tr><td>04.06.2026 09:18</td><td>account.access</td><td>Заблокирована</td><td class="text-good">Не заблокирована</td><td>AD snapshot</td><td>state projection job 00012</td></tr>
      </tbody></table></div></section>
    </div>`;
  }

  function entityFindings() {
    const detailed = can('finding.view');
    return `<div class="grid entity-layout">
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Находки по объекту</h2><p class="panel-subtitle">Риск, уверенность и полнота наблюдения не сворачиваются в один цвет.</p></div>${badge('2 открыты','warn')}</div><div class="panel-body risk-stack">
        <div class="risk-row"><div class="risk-marker bad"></div><div class="risk-content"><div class="risk-title">Вложенное членство в Backup Operators без подтверждённого владельца</div><div class="risk-copy">Наблюдение: CORP\\ivanov входит в IT-Helpdesk, которая вложена в Backup Operators. Вывод: доступ требует аттестации.</div><div class="item-meta"><span>Risk: высокий</span><span>Уверенность классификации: высокая</span><span>Покрытие: частичное из-за backlog DC1</span></div>${detailed ? `<div class="tech-only block" style="margin-top:8px"><span class="mono">rule: ad-privileged-path-without-owner v4</span></div>` : ''}</div><div class="risk-side">${badge('P1','bad')}${button('Проверить','eye',{small:true,attrs:'data-entity-tab="groups"'})}</div></div>
        <div class="risk-row"><div class="risk-marker warn"></div><div class="risk-content"><div class="risk-title">Пароль старше принятого порога контроля</div><div class="risk-copy">Пароль изменён 17.02.2026; возраст 153 дня при пороге 120. Это не означает компрометацию.</div><div class="item-meta"><span>Risk: средний</span><span>Уверенность: высокая</span><span>Покрытие: AD snapshot актуален</span></div>${detailed ? `<div class="tech-only block" style="margin-top:8px"><span class="mono">rule: ad-password-age v2 · threshold=120d</span></div>` : ''}</div><div class="risk-side">${badge('P2','warn')}${can('task.create') ? button('Создать задачу','case',{small:true,attrs:'data-toast-title="Задача создана" data-toast-copy="В задаче указано, что находка не доказывает компрометацию."'}) : ''}</div></div>
      </div></section>
      <aside class="section-stack">
        <section class="panel pad"><div class="eyebrow">Раздельные оси</div><h2 class="panel-title">Оценка первой находки</h2><div class="detail-list" style="margin-top:9px"><div class="detail-row"><dt>Риск</dt><dd>${badge('Высокий','bad')}</dd></div><div class="detail-row"><dt>Уверенность</dt><dd>${badge('Высокая','good')}</dd></div><div class="detail-row"><dt>Покрытие</dt><dd>${badge('Частичное','warn')}</dd></div><div class="detail-row"><dt>Режим</dt><dd>${badge('Legacy finding','neutral')}</dd></div></div></section>
        <section class="callout purple">${icon('info')}<div><div class="callout-title">Оператор и аналитик видят одну находку по-разному</div><div class="callout-copy">Оператор получает причину и действие. Аналитик дополнительно получает правило, факторы, точные события и ограничения. Дублировать сущность в двух системах не нужно.</div></div></section>
      </aside>
    </div>`;
  }

  function entityEvidence() {
    return `<div class="section-stack">
      <section class="callout good">${icon('check')}<div><div class="callout-title">Точные доказательства доступны</div><div class="callout-copy">Каждая строка содержит ID события в БД, источник, канал, UTC и роль объекта. Нажатие не запускает сбор или анализ.</div></div></section>
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Связанные события</h2><p class="panel-subtitle">Ограниченная выборка за последние 24 часа.</p></div>${button('Экспорт evidence bundle','download',{small:true,attrs:can('report.export')?'data-toast-title="Пакет подготовлен" data-toast-copy="Выгрузка включает provenance, точные ID и границы запроса."':'data-request-capability="report.export"'})}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>ID в БД</th><th>Время</th><th>Event ID</th><th>Что наблюдалось</th><th>Роль объекта</th><th>Источник</th><th>Открыть</th></tr></thead><tbody>${eventRows.map(row => `<tr><td class="mono">${row.db}</td><td>${row.time}</td><td>${row.eid}</td><td><div class="cell-primary">${row.title}</div><div class="cell-secondary">${row.actor} → ${row.target}</div></td><td>${row.target.includes('ivanov') ? badge('цель','accent') : badge('участник','neutral')}</td><td>${row.source}</td><td>${button('Карточка','eye',{small:true,attrs:`data-toast-title="Событие DB ${row.db}" data-toast-copy="Открывается точная карточка события с raw message, EventData и связями."`})}</td></tr>`).join('')}</tbody></table></div></section>
    </div>`;
  }

  function entityTechnical() {
    return `<div class="grid entity-layout">
      <section class="section-stack">
        <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Технические атрибуты AD</h2><p class="panel-subtitle">Раздел доступен только при разрешении entity.technical. Переключатель сверху управляет плотностью, но не выдаёт право.</p></div>${badge('AD snapshot','accent')}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Атрибут</th><th>Значение</th><th>Источник</th><th>Время</th></tr></thead><tbody>
          <tr><td class="mono">distinguishedName</td><td class="mono">CN=Иванов Иван Петрович,OU=Новокузнецк,OU=Users_KHV,DC=corp,DC=local</td><td>DC2 LDAP</td><td>14:02</td></tr>
          <tr><td class="mono">objectGUID</td><td class="mono">00000000-0000-4000-8000-000000000044</td><td>DC2 LDAP</td><td>14:02</td></tr>
          <tr><td class="mono">objectSid</td><td class="mono">S-1-5-21-…-4182</td><td>DC2 LDAP</td><td>14:02</td></tr>
          <tr><td class="mono">userAccountControl</td><td class="mono">512</td><td>DC2 LDAP</td><td>14:02</td></tr>
          <tr><td class="mono">pwdLastSet</td><td class="mono">134157984000000000</td><td>DC2 LDAP</td><td>14:02</td></tr>
          <tr><td class="mono">lastLogonTimestamp</td><td class="mono">134290541050000000</td><td>DC2 LDAP</td><td>14:02</td></tr>
          <tr class="tech-only"><td class="mono">snapshot_hash</td><td class="mono">sha256:fc0a4f…8d92</td><td>entity-state job 00015</td><td>14:03</td></tr>
          <tr class="tech-only"><td class="mono">source_object_key</td><td class="mono">ad://host5.example.invalid/guid/b0e27a8f…</td><td>Storage V2</td><td>14:03</td></tr>
        </tbody></table></div></section>
        <section class="panel pad tech-only block"><h2 class="panel-title">Нормализованный объект</h2><pre class="mono" style="white-space:pre-wrap;margin:12px 0 0;padding:13px;border:1px solid var(--line);border-radius:8px;background:#0b1d31;color:#d7e7f8;overflow:auto">{
  "entity_id": "ent_01J4F7M2YV",
  "type": "ad.user_account",
  "natural_keys": ["CORP\\\\ivanov", "ivanov@host5.example.invalid"],
  "linked_person_id": "person_004182",
  "observed_at": "2026-07-19T12:02:11Z",
  "source": "ad-snapshot/DC2",
  "projection_status": "conflict"
}</pre></section>
      </section>
      <aside class="section-stack">
        <section class="panel pad"><div class="eyebrow">Контроль доступа</div><h2 class="panel-title">Почему раздел виден</h2><div class="detail-list" style="margin-top:8px"><div class="detail-row"><dt>Возможность</dt><dd class="mono">entity.technical</dd></div><div class="detail-row"><dt>Источник</dt><dd>${accessSourceLabel()}</dd></div><div class="detail-row"><dt>Область</dt><dd>host5.example.invalid</dd></div></div>${button('Показать трассировку','branch',{small:true,attrs:'data-access-trace="entity.technical"',})}</section>
        <section class="callout warn">${icon('lock')}<div><div class="callout-title">Переключатель не повышает права</div><div class="callout-copy">Если разрешение отсутствует, вкладка не появляется, даже когда включён «Технический слой».</div></div></section>
      </aside>
    </div>`;
  }

  function problemsPage() {
    return `${prototypeBanner()}
      ${pageHead({eyebrow:`${badge('Рабочая очередь','warn')} <span>·</span> назначенный отчёт`,title:'Очередь проблем ИБ',subtitle:'Простой режим: увидеть проблему, понять вероятную причину и выполнить разрешённое действие. Переход в универсальную карточку объекта не требует отдельного приложения.',actions:button('Мой доступ','key',{attrs:'data-route="access-user"'})})}
      <section class="grid four" style="margin-bottom:14px">
        ${metric({label:'Критические',value:'1',caption:'требует решения сегодня',iconName:'warning',tone:'bad'})}
        ${metric({label:'Высокие',value:'1',caption:'назначить владельца',iconName:'warning',tone:'warn'})}
        ${metric({label:'Средние',value:'1',caption:'плановая проверка',iconName:'warning',tone:'accent'})}
        ${metric({label:'Передано в работу',value:'2',caption:'контроль результата',iconName:'case',tone:'good'})}
      </section>
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Требует решения</h2><p class="panel-subtitle">Причина подписана как гипотеза, если она ещё не доказана.</p></div>${badge('3 проблемы','outline')}</div><div class="panel-body card-list">
        <div class="list-item"><div class="risk-marker bad"></div><div class="item-main"><div class="item-title">CORP\\ivanov получил вложенную привилегию Backup Operators</div><div class="item-copy"><strong>Вероятная причина:</strong> пользователь входит в IT-Helpdesk, которую добавили в привилегированную группу. Подтверждённый владелец доступа не найден.</div><div class="item-meta"><span>P1</span><span>22 минуты назад</span><span>покрытие DC1 частичное</span></div></div><div class="item-actions">${button('Открыть карточку','entity',{kind:'primary',small:true,attrs:'data-route="entity" data-entity-tab="overview"'})}${can('case.create')?button('В расследование','case',{small:true,attrs:'data-toast-title="Расследование создано" data-toast-copy="Проблема и объект добавлены с указанием ограничения данных."'}):''}</div></div>
        <div class="list-item"><div class="risk-marker bad"></div><div class="item-main"><div class="item-title">Сервисная учётная запись svc-backup регулярно блокируется</div><div class="item-copy"><strong>Вероятная причина:</strong> служба на APP-SRV-03 может использовать старый пароль. Причина требует проверки ИТ.</div><div class="item-meta"><span>P1</span><span>17 минут назад</span><span>14 ошибок входа</span></div></div><div class="item-actions">${button('Передать ИТ','case',{kind:'primary',small:true,attrs:'data-toast-title="Задача передана" data-toast-copy="В задачу включены объект, предполагаемая причина и безопасные шаги проверки."'})}</div></div>
        <div class="list-item"><div class="risk-marker warn"></div><div class="item-main"><div class="item-title">На DC1 создана новая запланированная задача</div><div class="item-copy"><strong>Причина не установлена:</strong> событие подтверждает создание InventorySync учётной записью deploy.bot; назначение требует владельца.</div><div class="item-meta"><span>P2</span><span>53 минуты назад</span><span>вывод предварительный</span></div></div><div class="item-actions">${button('Создать проверку','case',{small:true,attrs:'data-toast-title="Проверка создана" data-toast-copy="Прямых изменений на DC не выполнялось."'})}</div></div>
      </div></section>`;
  }

  function eventsPage() {
    return `${prototypeBanner()}
      ${pageHead({eyebrow:`${badge('Evidence','accent')} <span>·</span> ограниченная выборка`,title:'События и доказательства',subtitle:'События не заменяют профиль объекта: из каждой строки можно открыть карточку пользователя, компьютера, группы или другого участника.',actions:button('Экспорт выборки','download',{attrs:can('report.export')?'data-toast-title="Экспорт подготовлен" data-toast-copy="Границы запроса и точные ID включены."':'data-request-capability="report.export"'})})}
      <section class="toolbar"><div class="field grow"><label>Поиск</label><div class="input-wrap">${icon('search')}<input value="CORP\\ivanov"></div></div><div class="field"><label>Период</label><select><option>Последние 24 часа</option></select></div><div class="field"><label>Источник</label><select><option>Все разрешённые</option><option>DC1</option><option>DC2</option></select></div>${button('Применить','filter',{kind:'primary',attrs:'data-toast-title="Фильтр применён" data-toast-copy="Запрос ограничен выбранным периодом и областью данных."'})}</section>
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">4 события</h2><p class="panel-subtitle">Точный ID в БД не смешивается с Windows Event ID.</p></div>${badge('has_more=false','outline')}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>ID в БД</th><th>Время</th><th>Event ID</th><th>Событие</th><th>Участники</th><th>Источник</th><th>Риск</th></tr></thead><tbody>${eventRows.map(row => `<tr><td class="mono">${row.db}</td><td>${row.time}</td><td>${row.eid}</td><td><div class="cell-primary">${row.title}</div><div class="cell-secondary tech-only">UTC и EventRecordID доступны в карточке события</div></td><td><button class="link-button" data-route="entity" data-entity-tab="overview">${row.actor}</button><div class="cell-secondary">→ <button class="link-button" data-route="entity" data-entity-tab="overview">${row.target}</button></div></td><td>${row.source}</td><td>${badge(row.risk,row.tone)}</td></tr>`).join('')}</tbody></table></div></section>`;
  }

  function casesPage() {
    return `${prototypeBanner()}
      ${pageHead({eyebrow:`${badge('Командная работа','purple')} <span>·</span> назначенный модуль`,title:'Расследования',subtitle:'Дело связывает объекты, находки и точные события, сохраняя источник, время, ограничения и решение аналитика.',actions:button('Создать дело','plus',{kind:'primary',attrs:'data-toast-title="Черновик дела" data-toast-copy="Сначала выберите исходный объект или точное событие."'})})}
      <section class="grid three">
        ${caseCard('CASE-2026-0041','Изменение привилегий CORP\\ivanov','На проверке','bad','А. Кузнецов','12 доказательств')}
        ${caseCard('CASE-2026-0038','Блокировки svc-backup','Открыто','accent','Н. Орлова','8 доказательств')}
        ${caseCard('CASE-2026-0033','Неожиданная задача InventorySync','Подтверждено','good','Д. Соколов','17 доказательств')}
      </section>`;
  }

  function caseCard(id,title,stateText,tone,owner,evidence) {
    return `<article class="panel pad"><div style="display:flex;justify-content:space-between;gap:10px"><div><div class="eyebrow">${id}</div><h2 class="panel-title">${title}</h2></div>${status(stateText,tone)}</div><div class="item-meta" style="margin-top:14px"><span>Ответственный: ${owner}</span><span>${evidence}</span><span>обновлено сегодня</span></div><div style="margin-top:14px">${button('Открыть дело','eye',{small:true,attrs:'data-toast-title="Карточка дела" data-toast-copy="Дело сохраняет confirmed/excluded evidence, заметки и решение."'})}</div></article>`;
  }

  function adReportIdentity(section) {
    return `<div class="callout" style="margin-bottom:14px">${icon('report')}<div><div class="callout-title">Отчёт: ${section}</div><div class="callout-copy">Снимок Active Directory от 17.07.2026 12:06 · домен example.invalid / демонстрационная область host5.example.invalid · источник данных виден в карточках объектов.</div></div></div>`;
  }

  function adReportPage() {
    return `${prototypeBanner()}
      ${pageHead({eyebrow:`${badge('Назначенный отчёт','accent')} <span>·</span> через группу AD · аудит`,title:'Состояние и риски Active Directory',subtitle:'Отчёт остаётся рабочей областью, но любая строка ведёт в универсальную карточку объекта. Отдельный отчёт можно выдать без назначения пользователю всего ИТ-интерфейса.',actions:`${button('Открыть карточку CORP\\ivanov','entity',{kind:'primary',attrs:'data-route="entity" data-entity-tab="overview"'})}${button('Почему у меня есть доступ','branch',{attrs:'data-access-trace="ad-summary"'})}`})}
      ${adReportIdentity('Сводка и приоритеты')}
      <section class="grid four" style="margin-bottom:14px">
        ${metric({label:'Критические категории',value:'1',caption:'DCSync · 8 записей',iconName:'warning',tone:'bad'})}
        ${metric({label:'Высокие категории',value:'4',caption:'Kerberos, LDAP, GPO, delegation',iconName:'warning',tone:'warn'})}
        ${metric({label:'Неактивные пользователи',value:'2 255',caption:'нужна сегментация перед очисткой',iconName:'users',tone:'accent'})}
        ${metric({label:'PasswordNeverExpires',value:'1 397',caption:'включая сервисные исключения',iconName:'key',tone:'warn'})}
      </section>
      <div class="grid main-aside">
        <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Рабочая очередь</h2><p class="panel-subtitle">Приоритет, объект, причина, следующий безопасный шаг и владелец.</p></div>${badge('6 направлений','outline')}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Приоритет</th><th>Область</th><th>Что обнаружено</th><th>Почему важно</th><th>Следующий шаг</th><th>Объект</th></tr></thead><tbody>
          <tr><td>${badge('P1','bad')}</td><td>DCSync</td><td><div class="cell-primary">8 записей прав репликации</div></td><td>Нестандартный субъект может получить доступ к секретам каталога.</td><td>Сверить с разрешённым перечнем и владельцами.</td><td><button class="link-button" data-route="objects">Группы и ACL</button></td></tr>
          <tr><td>${badge('P1','bad')}</td><td>LDAP</td><td><div class="cell-primary">Подписывание не требуется</div></td><td>Снижена защита LDAP-трафика.</td><td>Оценить совместимость, подготовить изменение и откат.</td><td><button class="link-button" data-route="objects">DC1</button></td></tr>
          <tr><td>${badge('P1','bad')}</td><td>Привилегии</td><td><div class="cell-primary">Новый путь к Backup Operators</div><div class="cell-secondary">CORP\\ivanov через IT-Helpdesk</div></td><td>Владелец и основание доступа не подтверждены.</td><td>Создать аттестацию доступа.</td><td><button class="link-button" data-route="entity" data-entity-tab="groups">CORP\\ivanov</button></td></tr>
          <tr><td>${badge('P2','warn')}</td><td>Учётные записи</td><td><div class="cell-primary">2 255 неактивных пользователей</div></td><td>Массовое отключение опасно без владельцев и сегментации.</td><td>Разделить пользовательские, сервисные и общие УЗ.</td><td><button class="link-button" data-route="objects">Пользователи</button></td></tr>
          <tr><td>${badge('P2','warn')}</td><td>Компьютеры</td><td><div class="cell-primary">21 устаревшая ОС</div></td><td>Активные системы требуют миграции или изоляции.</td><td>Отделить активные системы от кандидатов на очистку.</td><td><button class="link-button" data-route="objects">Компьютеры</button></td></tr>
          <tr><td>${badge('P2','warn')}</td><td>GPO</td><td><div class="cell-primary">77 политик требуют проверки</div></td><td>Есть старые и недокументированные политики и скрипты.</td><td>Начать с P1, сделать backup и план отката.</td><td><button class="link-button" data-route="gpo-report">GPO</button></td></tr>
        </tbody></table></div></section>
        <aside class="section-stack">
          <section class="panel pad"><div class="eyebrow">Быстрые переходы</div><h2 class="panel-title">Разделы отчёта</h2><div class="card-list" style="margin-top:12px">
            <div class="list-item"><div class="item-main"><div class="item-title">Домен и DC</div><div class="item-copy">Репликация, схема, LDAP, доверия.</div></div>${icon('chevron')}</div>
            <div class="list-item"><div class="item-main"><div class="item-title">Учётные записи</div><div class="item-copy">Неактивные, пароли, привилегии.</div></div>${icon('chevron')}</div>
            <div class="list-item"><div class="item-main"><div class="item-title"><button class="link-button" data-route="gpo-report">GPO</button></div><div class="item-copy">Ручная проверка и governance.</div></div>${icon('chevron')}</div>
          </div></section>
          <section class="callout good">${icon('link')}<div><div class="callout-title">Отчёт и карточка используют один объект</div><div class="callout-copy">ФИО, контакты, группы, состояния, события и задачи не копируются внутрь каждого отчёта. Отчёт хранит фильтр и представление, а объект — единый контекст.</div></div></section>
        </aside>
      </div>`;
  }

  function gpoReportPage() {
    return `${prototypeBanner()}
      ${pageHead({eyebrow:`${badge('Назначенный отчёт','warn')} <span>·</span> GPO governance`,title:'GPO — очередь ручной проверки',subtitle:'Отчёт публикуется как отдельный модуль. Доступ можно дать аудитору GPO, не открывая ему события ИБ или техническую эксплуатацию проекта.',actions:`${button('Создать задачу проверки','plus',{kind:'primary',attrs:'data-toast-title="Задача создана" data-toast-copy="GPO, приоритет, владелец, backup и план отката добавлены в задачу."'})}${button('Почему у меня есть доступ','branch',{attrs:'data-access-trace="gpo-review"'})}`})}
      ${adReportIdentity('GPO')}
      <section class="grid four" style="margin-bottom:14px">
        ${metric({label:'Всего GPO',value:'77',caption:'в очереди governance',iconName:'settings',tone:'accent'})}
        ${metric({label:'P1',value:'1',caption:'проверить немедленно',iconName:'warning',tone:'bad'})}
        ${metric({label:'Со скриптами',value:'41',caption:'GPMC + SYSVOL',iconName:'code',tone:'warn'})}
        ${metric({label:'Старше срока',value:'71',caption:'нужен пересмотр владельца',iconName:'clock',tone:'warn'})}
      </section>
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Политики для проверки</h2><p class="panel-subtitle">Никаких прямых кнопок удаления или изменения GPO.</p></div>${badge('показано 5 из 77','outline')}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Приоритет</th><th>GPO</th><th>Область</th><th>Причина</th><th>Владелец</th><th>Безопасный следующий шаг</th><th>Состояние</th></tr></thead><tbody>
        <tr><td>${badge('P1','bad')}</td><td><div class="cell-primary">Legacy Domain Admin Logon</div><div class="cell-secondary mono">{A7F1…0C21}</div></td><td>Domain Controllers</td><td>Скрипт входа и отсутствие подтверждённого владельца.</td><td class="text-bad">Не указан</td><td>Проверить GPMC/SYSVOL, сделать backup, определить откат.</td><td>${status('Не назначено','bad')}</td></tr>
        <tr><td>${badge('P2','warn')}</td><td><div class="cell-primary">Helpdesk Remote Access</div><div class="cell-secondary mono">{44D2…F092}</div></td><td>OU=Support-Servers</td><td>Даёт RDP/WinRM группе IT-Helpdesk.</td><td>ИТ-служба</td><td>Сверить участников и срок аттестации.</td><td>${status('В работе','accent')}</td></tr>
        <tr><td>${badge('P2','warn')}</td><td><div class="cell-primary">Workstation Security Baseline</div><div class="cell-secondary mono">{4A91…E331}</div></td><td>Рабочие станции</td><td>Последний утверждённый пересмотр более года назад.</td><td>ИБ</td><td>Сравнить с текущим baseline и исключениями.</td><td>${status('Запланировано','good')}</td></tr>
        <tr><td>${badge('P3','accent')}</td><td><div class="cell-primary">Printer Mapping NVKZ</div></td><td>OU=Новокузнецк</td><td>Старый скрипт, нет описания назначения.</td><td>ИТ-служба</td><td>Подтвердить использование и владельца.</td><td>${status('Нужна оценка','warn')}</td></tr>
        <tr><td>${badge('P4','good')}</td><td><div class="cell-primary">Corporate Wallpaper</div></td><td>Пользователи</td><td>Требуется документирование.</td><td>Маркетинг</td><td>Добавить описание и срок пересмотра.</td><td>${status('Планово','neutral')}</td></tr>
      </tbody></table></div></section>`;
  }

  function privilegedReportPage() {
    return `${prototypeBanner()}
      ${pageHead({eyebrow:`${badge('Прямое назначение','purple')} <span>·</span> до 31.12.2026`,title:'Привилегированные учётные записи',subtitle:'Этот отчёт выдан Алексею напрямую поверх двух групповых пакетов. По окончании срока он исчезнет из меню, не затрагивая остальные доступы.',actions:`${button('Открыть CORP\\ivanov','entity',{kind:'primary',attrs:'data-route="entity" data-entity-tab="privileges"'})}${button('Трассировка доступа','branch',{attrs:'data-access-trace="privileged-accounts"'})}`})}
      <section class="callout purple">${icon('clock')}<div><div class="callout-title">Временный доступ</div><div class="callout-copy">Основание: «Распоряжение ИБ-128». Область: host5.example.invalid. Уровень: анализ. Срок: 31.12.2026. Экспорт проверяется отдельным разрешением.</div></div></section>
      <section class="grid four" style="margin:14px 0">
        ${metric({label:'Активные привилегированные',value:'29',caption:'из предоставленного AD-аудита',iconName:'key',tone:'bad'})}
        ${metric({label:'Отключённые в группах',value:'16',caption:'требуют очистки членства',iconName:'lock',tone:'warn'})}
        ${metric({label:'PasswordNeverExpires',value:'40',caption:'среди привилегированных',iconName:'warning',tone:'warn'})}
        ${metric({label:'Без владельца',value:'6',caption:'в демонстрационной выборке',iconName:'users',tone:'accent'})}
      </section>
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Приоритетная выборка</h2><p class="panel-subtitle">ФИО и контакты показываются только при разрешениях pii.hr и pii.contact.</p></div>${button('Экспорт','download',{small:true,attrs:can('report.export')?'data-toast-title="Экспорт подготовлен" data-toast-copy="Контактные поля включены, поскольку разрешение pii.contact действует в host5.example.invalid."':'data-request-capability="report.export"'})}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Пользователь</th><th>Привилегия</th><th>Путь</th><th>Активность</th><th>Пароль</th><th>Владелец</th><th>Оценка</th></tr></thead><tbody>
        <tr><td><button class="link-button" data-route="entity" data-entity-tab="overview">Иванов Иван Петрович</button><div class="cell-secondary mono">CORP\\ivanov</div></td><td>Backup Operators</td><td>IT-Helpdesk → Backup Operators</td><td>Сегодня 12:48</td><td>153 дня</td><td class="text-bad">Не подтверждён</td><td>${badge('P1','bad')}</td></tr>
        <tr><td><div class="cell-primary">Кузнецов Алексей Сергеевич</div><div class="cell-secondary mono">CORP\\adm.kuznetsov</div></td><td>Domain Admins</td><td>Прямое членство</td><td>Сегодня 13:37</td><td>42 дня</td><td>Начальник ИТ</td><td>${badge('Аттестован','good')}</td></tr>
        <tr><td><div class="cell-primary">svc-adfs</div><div class="cell-secondary mono">CORP\\svc-adfs</div></td><td>SPN / сервис</td><td>host/adfs.host5.example.invalid</td><td>Сегодня 09:11</td><td class="text-bad">1 781 день</td><td>Не указан</td><td>${badge('P1','bad')}</td></tr>
        <tr><td><div class="cell-primary">svc-backup</div><div class="cell-secondary mono">CORP\\svc-backup</div></td><td>Backup Operators</td><td>Прямое членство</td><td>Заблокирована</td><td>91 день</td><td>Инфраструктура</td><td>${badge('P1','bad')}</td></tr>
      </tbody></table></div></section>`;
  }

  function vpnReportPage() {
    return `${prototypeBanner()}
      ${pageHead({eyebrow:`${badge('Назначенный отчёт','purple')} <span>·</span> VPN`,title:'VPN-доступ и актуальность владельцев',subtitle:'Отдельный отчёт можно запросить или назначить конкретной группе без расширения доступа к другим данным.',actions:button('Открыть карточку пользователя','entity',{kind:'primary',attrs:'data-route="entity" data-entity-tab="privileges"'})})}
      <section class="grid four" style="margin-bottom:14px">
        ${metric({label:'Всего VPN-пользователей',value:'430',caption:'группа VPNl2tp',iconName:'lock',tone:'accent'})}
        ${metric({label:'Активные',value:'418',caption:'учётные записи включены',iconName:'check',tone:'good'})}
        ${metric({label:'Отключённые',value:'12',caption:'остаются в группе',iconName:'warning',tone:'warn'})}
        ${metric({label:'VPN + привилегии',value:'9',caption:'повышенный контроль',iconName:'key',tone:'bad'})}
      </section>
      <section class="panel pad"><h2 class="panel-title">Пример отдельного отчёта</h2><p class="page-subtitle">В полной реализации здесь используется тот же зарегистрированный набор объектов и полей, что в карточке, а не копия данных из HTML.</p></section>`;
  }

  function projectReadinessPage() {
    return `${prototypeBanner()}
      ${pageHead({eyebrow:`${badge('Эксплуатация проекта','good')} <span>·</span> не ИТ-отчёт AD`,title:'Готовность и устойчивость проекта',subtitle:'Техническое состояние платформы доступно группе эксплуатации проекта. Администратор доступа может управлять публикацией, не получая автоматически доступ к персональным данным AD.',actions:button('Технические события','code',{kind:'primary',attrs:'data-toast-title="Журнал платформы" data-toast-copy="В рабочей версии откроется отдельный журнал сбора, обработки и хранения."'})})}
      <section class="grid four" style="margin-bottom:14px">
        ${metric({label:'PostgreSQL',value:'Работает',caption:'marker 31',iconName:'database',tone:'good'})}
        ${metric({label:'PITR',value:'Недоступен',caption:'archive_mode=off',iconName:'warning',tone:'bad'})}
        ${metric({label:'Entity state',value:'Активен',caption:'15/15 jobs completed',iconName:'layers',tone:'good'})}
        ${metric({label:'Semantic worker',value:'Не включён',caption:'служба не зарегистрирована',iconName:'code',tone:'accent'})}
      </section>
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Проверка готовности</h2><p class="panel-subtitle">«Недоступно» и «ошибка проверки» — разные состояния.</p></div></div><div class="table-wrap"><table class="data-table"><thead><tr><th>Проверка</th><th>Состояние</th><th>Что это означает</th><th>Следующий шаг</th></tr></thead><tbody>
        <tr><td>Runtime PostgreSQL</td><td>${status('Пройдено','good')}</td><td>Основная БД доступна, marker 31.</td><td>Наблюдать.</td></tr>
        <tr><td>Независимая копия</td><td>${status('Частично готово','warn')}</td><td>Backup есть, регулярная restore drill не принята.</td><td>Запланировать проверку восстановления.</td></tr>
        <tr><td>PITR / WAL archive</td><td>${status('Недоступно','bad')}</td><td>archive_mode=off, восстановление по времени невозможно.</td><td>Отдельный проект PITR-ARCHIVE-1.</td></tr>
        <tr><td>Semantic execution</td><td>${status('Не включено','neutral')}</td><td>Схема установлена, выполнение намеренно выключено.</td><td>Не активировать из этого экрана.</td></tr>
        <tr><td>Проверка внешнего архива</td><td>${status('Ошибка проверки','bad')}</td><td>Не удалось получить ответ от test endpoint; состояние функции неизвестно.</td><td>Проверить диагностику, не считать unavailable.</td></tr>
      </tbody></table></div></section>`;
  }

  function accessCenterPage() {
    return `${prototypeBanner()}
      ${pageHead({eyebrow:`${badge('Администрирование','accent')} <span>·</span> составной доступ`,title:'Доступы пользователей и групп',subtitle:'Администратор назначает не одну взаимоисключающую роль, а пакеты возможностей, отчёты, область данных, категории полей, действия и срок. Итоговый доступ можно проверить до сохранения.',actions:`${button('Выдать доступ','plus',{kind:'primary',attrs:'data-open-grant="alex"'})}${button('Публикация отчётов','report',{attrs:'data-route="report-management"'})}`})}
      <section class="callout good">${icon('check')}<div><div class="callout-title">Главное изменение модели</div><div class="callout-copy">«ИБ-оператор», «аналитик», «AD-аудитор» и «администратор проекта» становятся пакетами возможностей, а не единственным профилем пользователя. Отчёт может назначаться отдельно пользователю или группе.</div></div></section>
      <section class="access-model" style="margin:14px 0">
        <article class="access-layer"><div class="layer-number">1</div><div class="layer-title">Пользователь и группы</div><div class="layer-copy">Один человек состоит в нескольких функциональных и организационных группах.</div></article>
        <article class="access-layer"><div class="layer-number">2</div><div class="layer-title">Возможности</div><div class="layer-copy">Просмотр, расследование, создание задач, экспорт, публикация, администрирование.</div></article>
        <article class="access-layer"><div class="layer-number">3</div><div class="layer-title">Отчёты и модули</div><div class="layer-copy">Конкретные рабочие области назначаются независимо и могут иметь срок.</div></article>
        <article class="access-layer"><div class="layer-number">4</div><div class="layer-title">Данные и поля</div><div class="layer-copy">Домен, OU, источник, персональные и технические поля проверяются сервером.</div></article>
      </section>
      <section class="grid four" style="margin-bottom:14px">
        ${metric({label:'Пользователи',value:'24',caption:'4 показаны в прототипе',iconName:'user',tone:'accent'})}
        ${metric({label:'Группы доступа',value:'7',caption:'4 системных пакета',iconName:'users',tone:'good'})}
        ${metric({label:'Опубликованные отчёты',value:String(Object.keys(reports).length),caption:'назначаются отдельно',iconName:'report',tone:'accent'})}
        ${metric({label:'Истекают за 30 дней',value:'3',caption:'нужен пересмотр',iconName:'clock',tone:'warn'})}
      </section>
      <div class="grid main-aside">
        <section class="section-stack">
          <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Пользователи</h2><p class="panel-subtitle">Показан эффективный результат, а не только поле «роль».</p></div>${badge('4 записи','outline')}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Пользователь</th><th>Пакеты</th><th>Отчёты</th><th>Прямые назначения</th><th>Область</th><th>Контроль</th><th></th></tr></thead><tbody>
            ${Object.values(users).map(userAccessRow).join('')}
          </tbody></table></div></section>
          <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Журнал изменений доступа</h2><p class="panel-subtitle">Кто, что, кому, на каком основании и до какого срока.</p></div>${button('Выгрузить аудит','download',{small:true,attrs:'data-toast-title="Аудит подготовлен" data-toast-copy="Выгрузка содержит субъект, ресурс, scope, effect, основание и автора изменения."'})}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Время</th><th>Администратор</th><th>Изменение</th><th>Субъект</th><th>Основание</th></tr></thead><tbody>
            <tr><td>19.07.2026 13:10</td><td>Елена В.</td><td>Назначен отчёт «Привилегированные учётные записи» до 31.12.2026</td><td>Алексей К.</td><td>ИБ-128</td></tr>
            <tr><td>18.07.2026 16:42</td><td>Елена В.</td><td>Добавлен в группу AD · аудит</td><td>Дмитрий С.</td><td>Проект PAM-26</td></tr>
            <tr><td>17.07.2026 09:21</td><td>Система</td><td>Истёк доступ к отчёту VPN</td><td>Внешний аудитор</td><td>Срок завершён</td></tr>
          </tbody></table></div></section>
        </section>
        <aside class="section-stack">
          <section class="panel pad"><div class="eyebrow">Пакеты возможностей</div><h2 class="panel-title">Использовать как шаблоны</h2><div class="card-list" style="margin-top:12px">${Object.entries(accessGroups).map(([id,g]) => `<div class="list-item"><div class="item-main"><div class="item-title">${g.label}</div><div class="item-copy">${g.capabilities.length} возможностей · ${g.reportGrants.length} отчётов</div></div>${badge(g.type.includes('Административная')?'admin':'пакет',g.type.includes('Административная')?'purple':'neutral')}</div>`).join('')}</div></section>
          <section class="callout warn">${icon('warning')}<div><div class="callout-title">Администратор доступа не получает данные автоматически</div><div class="callout-copy">Возможность выдавать отчёты не должна сама по себе открывать персональные данные, события ИБ или AD. Управление доступом и чтение содержания — разные права.</div></div></section>
        </aside>
      </div>`;
  }

  function userAccessRow(user) {
    const access = effectiveAccess(user.id);
    const scope = [...access.scopes].filter(v => v !== 'all-subjects').join(', ') || 'только метаданные доступа';
    const expiry = user.directGrants.length ? status('Есть временный доступ','warn') : status('Без замечаний','good');
    return `<tr><td><div class="cell-primary">${user.name}</div><div class="cell-secondary">${user.title}</div></td><td><div class="cell-tags">${user.groups.map(id => badge(accessGroups[id].label,'neutral')).join('')}</div></td><td>${access.reportMap.size}</td><td>${user.directGrants.length}</td><td>${scope}</td><td>${expiry}</td><td>${button('Открыть','eye',{small:true,attrs:`data-select-access-user="${user.id}"`})}</td></tr>`;
  }

  function accessUserPage() {
    const targetId = can('access.manage') ? state.selectedAccessUser : state.userId;
    const target = users[targetId];
    const access = effectiveAccess(targetId);
    const canEdit = can('access.manage');
    const reportRows = [...access.reportMap.entries()].map(([reportId, grants]) => {
      const r = reports[reportId];
      const primary = grants[0];
      return `<tr><td><div class="cell-primary">${r.title}</div><div class="cell-secondary mono">${reportId}</div></td><td>${badge(primary.level, primary.level === 'Анализ' ? 'accent' : primary.level === 'Эксплуатация' ? 'good' : 'neutral')}</td><td>${primary.scope}</td><td><div class="cell-primary">${primary.source}</div><div class="cell-secondary">${primary.sourceType === 'direct' ? 'прямое назначение' : 'через группу'}</div></td><td>${primary.validUntil === 'Бессрочно' ? status('Бессрочно','good') : status(primary.validUntil,'warn')}</td><td>${button('Почему?','branch',{small:true,attrs:`data-access-trace="${reportId}" data-trace-user="${targetId}"`})}</td></tr>`;
    }).join('');
    const headerActions = canEdit
      ? `${button('Выдать доступ','plus',{kind:'primary',attrs:`data-open-grant="${targetId}"`})}${button('Предпросмотр от имени','eye',{attrs:`data-preview-user="${targetId}"`})}`
      : button('Запросить дополнительный отчёт','key',{kind:'primary',attrs:'data-route="reports"'});

    return `${prototypeBanner()}
      ${pageHead({eyebrow:`${badge(canEdit ? 'Администрирование' : 'Мой доступ',canEdit?'accent':'purple')} <span>·</span> эффективный результат`,title:canEdit ? 'Доступ пользователя' : 'Мои отчёты и права',subtitle:'Здесь видно не только что разрешено, но и почему, в какой области, до какого срока и какие поля остаются скрытыми.',actions:headerActions})}
      ${canEdit ? `<section class="toolbar"><div class="field"><label>Пользователь</label><select id="access-user-select">${Object.values(users).map(u => `<option value="${u.id}" ${u.id===targetId?'selected':''}>${u.name}</option>`).join('')}</select></div><div class="field grow"><label>Проверка</label><div class="input-wrap">${icon('search')}<input placeholder="Отчёт, возможность или область данных"></div></div>${button('Пересчитать доступ','check',{attrs:'data-toast-title="Доступ пересчитан" data-toast-copy="Учтены группы, прямые назначения, сроки, scope и ограничения полей."'})}</section>` : ''}
      <section class="panel" style="margin-bottom:14px"><div class="user-detail-head"><span class="avatar">${target.initials}</span><div class="user-detail-main"><h2 class="user-detail-name">${target.name}</h2><div class="user-detail-copy">${target.title}</div><div class="cell-tags" style="margin-top:8px">${target.groups.map(id => badge(accessGroups[id].label,id==='access-admins'?'purple':'neutral')).join('')}</div></div><div class="user-detail-actions">${canEdit ? button('Отключить вход','lock',{small:true,kind:'danger',attrs:'data-toast-title="Подтверждение требуется" data-toast-copy="Отключение пользователя и отзыв сессий выполняются отдельным подтверждаемым действием."'}) : ''}</div></div><div class="access-kpis"><div class="access-kpi"><strong>${target.groups.length}</strong><span>пакета доступа</span></div><div class="access-kpi"><strong>${access.reportMap.size}</strong><span>отчётов</span></div><div class="access-kpi"><strong>${target.directGrants.length}</strong><span>прямых назначений</span></div><div class="access-kpi"><strong>${access.capabilities.size}</strong><span>возможностей</span></div><div class="access-kpi"><strong>${access.fields.size}</strong><span>категорий полей</span></div></div></section>
      <div class="grid main-aside">
        <section class="section-stack">
          <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Доступные отчёты</h2><p class="panel-subtitle">Один и тот же пользователь получает отчёты из разных источников.</p></div>${badge(`${access.reportMap.size} отчётов`,'outline')}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Отчёт</th><th>Уровень</th><th>Область</th><th>Источник доступа</th><th>Срок</th><th>Трассировка</th></tr></thead><tbody>${reportRows || '<tr><td colspan="6"><div class="empty-state">Отчёты не назначены</div></td></tr>'}</tbody></table></div></section>
          <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Возможности и действия</h2><p class="panel-subtitle">Пакеты можно комбинировать; конфликтующие запреты должны иметь приоритет.</p></div></div><div class="panel-body"><div class="cell-tags">${[...access.capabilities].sort().map(c => badge(c,c.includes('manage')||c.includes('publish')?'purple':c.includes('view')?'accent':'neutral')).join('')}</div></div></section>
        </section>
        <aside class="section-stack">
          <section class="panel pad"><div class="eyebrow">Область данных</div><h2 class="panel-title">Где действует доступ</h2><div class="detail-list" style="margin-top:8px">${[...access.scopes].map(scope => `<div class="detail-row"><dt>Scope</dt><dd>${scope}</dd></div>`).join('')}</div></section>
          <section class="panel pad"><div class="eyebrow">Категории полей</div><h2 class="panel-title">Что можно видеть</h2><div class="card-list" style="margin-top:12px">${fieldAccessRows(access.fields)}</div></section>
          ${target.directGrants.length ? `<section class="callout warn">${icon('clock')}<div><div class="callout-title">Есть временные назначения</div><div class="callout-copy">${target.directGrants.map(g => `${reports[g.reportId].title} — до ${g.validUntil}`).join('; ')}. За 30 дней до окончания нужен пересмотр.</div></div></section>` : ''}
        </aside>
      </div>`;
  }

  function fieldAccessRows(fields) {
    const definitions = [
      ['identity.basic','Базовая идентификация','ФИО, логин, UPN, статус'],
      ['pii.contact','Контактные данные','email и рабочий телефон'],
      ['pii.hr','Кадровые атрибуты','должность, отдел, руководитель, табельный номер'],
      ['ad.attributes','Расширенные AD-поля','OU, состояние пароля и учётной записи'],
      ['technical.raw','Исходные технические поля','raw event, GUID, SID, EventData'],
      ['platform.technical','Технические данные проекта','очереди, workers, storage'],
      ['access.metadata','Метаданные доступа','назначения без содержимого отчётов']
    ];
    return definitions.map(([id,title,copy]) => `<div class="list-item"><div class="item-main"><div class="item-title">${title}</div><div class="item-copy">${copy}</div></div>${fields.has(id) ? status('Разрешено','good') : status('Не разрешено','neutral')}</div>`).join('');
  }

  function reportManagementPage() {
    const assignmentMap = {
      'security-queue':'ИБ · операторы', 'security-events':'ИБ · аналитики', investigations:'ИБ · аналитики',
      'ad-summary':'AD · аудит', 'gpo-review':'AD · аудит', 'privileged-accounts':'2 пользователя напрямую',
      'vpn-audit':'не опубликован', 'project-readiness':'Проект · эксплуатация', 'technical-events':'Проект · эксплуатация'
    };
    return `${prototypeBanner()}
      ${pageHead({eyebrow:`${badge('Администрирование','accent')} <span>·</span> каталог модулей`,title:'Публикация и доступ к отчётам',subtitle:'Отчёт — самостоятельный ресурс с владельцем, версией, набором данных, обязательными правами, чувствительностью и назначениями пользователям или группам.',actions:`${button('Создать отчёт','plus',{kind:'primary',attrs:'data-route="report-editor"'})}${button('Доступы пользователей','users',{attrs:'data-route="access-center"'})}`})}
      <section class="callout">${icon('lock')}<div><div class="callout-title">Публикация не даёт обходить защиту данных</div><div class="callout-copy">Определение отчёта хранит только разрешённый dataset, поля, фильтры, визуализации и действия. Произвольный SQL в браузере не допускается. При открытии сервер повторно проверяет report.view, scope и field permissions.</div></div></section>
      <section class="grid four" style="margin:14px 0">
        ${metric({label:'Опубликовано',value:'8',caption:'1 отчёт пока не назначен',iconName:'report',tone:'good'})}
        ${metric({label:'Наборы данных',value:'7',caption:'зарегистрированные контракты',iconName:'database',tone:'accent'})}
        ${metric({label:'Временные назначения',value:'3',caption:'контроль срока',iconName:'clock',tone:'warn'})}
        ${metric({label:'Требуют пересмотра',value:'1',caption:'VPN-аудит без аудитории',iconName:'warning',tone:'warn'})}
      </section>
      <section class="panel"><div class="panel-head"><div><h2 class="panel-title">Реестр отчётов</h2><p class="panel-subtitle">Каждый отчёт версионируется и имеет владельца.</p></div>${badge(`${Object.keys(reports).length} определений`,'outline')}</div><div class="table-wrap"><table class="data-table"><thead><tr><th>Отчёт</th><th>Dataset</th><th>Владелец</th><th>Чувствительность</th><th>Кому доступен</th><th>Версия</th><th>Действия</th></tr></thead><tbody>${Object.values(reports).map(r => `<tr><td><div class="cell-primary">${r.title}</div><div class="cell-tags">${r.tags.map(t => badge(t,'neutral')).join('')}</div></td><td class="mono">${r.dataset}</td><td>${r.owner}</td><td>${r.sensitivity}</td><td>${assignmentMap[r.id]}</td><td>${r.version}</td><td><div class="item-actions">${button('Назначить','key',{small:true,attrs:`data-publish-report="${r.id}"`})}${button('Клонировать','copy',{small:true,attrs:'data-route="report-editor"'})}</div></td></tr>`).join('')}</tbody></table></div></section>`;
  }

  const builderFields = [
    { id:'display_name', label:'Полное ФИО', source:'identity.basic', sensitivity:'Базовые', checked:true },
    { id:'account_name', label:'Логин', source:'ad.user', sensitivity:'Базовые', checked:true },
    { id:'email', label:'Рабочая почта', source:'pii.contact', sensitivity:'Контактные', checked:true },
    { id:'department', label:'Отдел', source:'pii.hr', sensitivity:'Кадровые', checked:true },
    { id:'privilege', label:'Эффективная привилегия', source:'ad.relations', sensitivity:'Технические', checked:true },
    { id:'path', label:'Путь получения', source:'ad.relations', sensitivity:'Технические', checked:true },
    { id:'last_logon', label:'Последний вход', source:'ad.state', sensitivity:'Технические', checked:true },
    { id:'password_age', label:'Возраст пароля', source:'ad.state', sensitivity:'Технические', checked:false },
    { id:'phone', label:'Рабочий телефон', source:'pii.contact', sensitivity:'Контактные', checked:false },
    { id:'object_sid', label:'SID', source:'technical.raw', sensitivity:'Технические raw', checked:false }
  ];

  function reportEditorPage() {
    return `${prototypeBanner()}
      ${pageHead({eyebrow:`${badge('Конструктор','purple')} <span>·</span> безопасное представление`,title:'Новый отчёт: аттестация привилегий',subtitle:'Конструктор использует зарегистрированные datasets и поля. Он создаёт версионируемое представление, а не произвольный запрос к базе.',actions:`${button('Сохранить черновик','save',{attrs:'data-save-report="draft"'})}${button('Опубликовать','check',{kind:'primary',attrs:'data-save-report="publish"'})}`})}
      <div class="report-builder">
        <aside class="panel pad">
          <div class="builder-section"><h2 class="builder-title">Основные параметры</h2><div class="field"><label>Название</label><input id="builder-title" value="Аттестация привилегированных учётных записей"></div><div class="field" style="margin-top:9px"><label>Набор данных</label><select><option>ad.accounts.privileged</option><option>ad.users</option><option>ad.relations.membership</option></select></div><div class="field" style="margin-top:9px"><label>Владелец</label><select><option>ИБ + ИТ</option><option>ИТ-служба</option><option>Отдел ИБ</option></select></div></div>
          <div class="builder-section"><h2 class="builder-title">Поля отчёта</h2><div class="field-picker">${builderFields.map(f => `<label class="field-option"><input type="checkbox" data-builder-field="${f.id}" ${f.checked?'checked':''}><span class="field-option-main"><span class="field-option-name">${f.label}</span><span class="field-option-meta">${f.source} · ${f.sensitivity}</span></span>${badge(f.sensitivity,f.sensitivity.includes('Контакт')?'purple':f.sensitivity.includes('raw')?'warn':'neutral')}</label>`).join('')}</div></div>
          <div class="builder-section"><h2 class="builder-title">Фильтры по умолчанию</h2><div class="field"><label>Условие 1</label><select><option>account.enabled = true</option></select></div><div class="field" style="margin-top:8px"><label>Условие 2</label><select><option>privilege.level in (high, critical)</option></select></div></div>
          <div class="builder-section"><h2 class="builder-title">Переходы и действия</h2><label class="field-option"><input type="checkbox" checked><span class="field-option-main"><span class="field-option-name">Открывать карточку объекта</span><span class="field-option-meta">Сохранять return path и фильтры</span></span></label><label class="field-option" style="margin-top:6px"><input type="checkbox" checked><span class="field-option-main"><span class="field-option-name">Создать задачу аттестации</span><span class="field-option-meta">Требуется task.create</span></span></label><label class="field-option" style="margin-top:6px"><input type="checkbox"><span class="field-option-main"><span class="field-option-name">Экспорт CSV</span><span class="field-option-meta">Требуется report.export</span></span></label></div>
        </aside>
        <section class="builder-preview section-stack">
          <section class="callout good">${icon('check')}<div><div class="callout-title">Проверка контракта пройдена</div><div class="callout-copy">Все выбранные поля зарегистрированы. Для email нужен pii.contact; пользователи без этого права увидят колонку скрытой или отчёт без неё — по политике отчёта.</div></div></section>
          <section class="panel"><div class="panel-head"><div><h2 class="panel-title" id="builder-preview-title">Аттестация привилегированных учётных записей</h2><p class="panel-subtitle">Предпросмотр · host5.example.invalid · 4 строки из 29</p></div>${badge('Черновик v0.1','purple')}</div><div class="table-wrap" id="builder-preview"></div></section>
          <section class="grid two">
            <article class="panel pad"><div class="eyebrow">Требования доступа</div><h2 class="panel-title">Автоматически вычислено</h2><div class="cell-tags" style="margin-top:12px">${badge('report.view:custom_privileged','accent')}${badge('scope:host5.example.invalid','neutral')}${badge('pii.contact','purple')}${badge('entity.privileges','warn')}</div></article>
            <article class="panel pad"><div class="eyebrow">Публикация</div><h2 class="panel-title">Кому будет доступен</h2><div class="field" style="margin-top:10px"><label>Пользователь или группа</label><select><option>Не выбрано</option><option>AD · аудит и сопровождение</option><option>ИБ · аналитики</option><option>Алексей Кузнецов</option></select></div></article>
          </section>
          <section class="callout warn">${icon('warning')}<div><div class="callout-title">Не превращать конструктор в SQL-консоль</div><div class="callout-copy">Новые типы данных добавляются backend-плагином: schema, поля, sensitivity, фильтры, связи, действия и правила доступа. UI подхватывает контракт и не требует переписывать всю карточку.</div></div></section>
        </section>
      </div>`;
  }

  function updateBuilderPreview() {
    const root = $('#builder-preview');
    if (!root) return;
    const selected = new Set($$('[data-builder-field]:checked').map(el => el.dataset.builderField));
    const columns = builderFields.filter(f => selected.has(f.id));
    const values = {
      display_name:['Иванов Иван Петрович','Кузнецов Алексей Сергеевич','svc-adfs','svc-backup'],
      account_name:['CORP\\ivanov','CORP\\adm.kuznetsov','CORP\\svc-adfs','CORP\\svc-backup'],
      email:['i.ivanov@corp.example.test','a.kuznetsov@corp.example.test','—','—'],
      department:['ИТ-служба','ИТ-служба','Сервисы идентификации','Инфраструктура'],
      privilege:['Backup Operators','Domain Admins','SPN / сервис','Backup Operators'],
      path:['IT-Helpdesk → Backup Operators','Прямое членство','host/adfs.host5.example.invalid','Прямое членство'],
      last_logon:['Сегодня 12:48','Сегодня 13:37','Сегодня 09:11','Заблокирована'],
      password_age:['153 дня','42 дня','1 781 день','91 день'],
      phone:['доб. 418','доб. 112','—','—'],
      object_sid:['S-1-5-21-…-4182','S-1-5-21-…-1102','S-1-5-21-…-2211','S-1-5-21-…-3012']
    };
    root.innerHTML = `<table class="data-table"><thead><tr>${columns.map(c => `<th>${c.label}</th>`).join('')}<th>Оценка</th></tr></thead><tbody>${[0,1,2,3].map(row => `<tr>${columns.map(c => `<td>${c.id==='display_name' ? `<button class="link-button" data-route="entity" data-entity-tab="overview">${values[c.id][row]}</button>` : values[c.id][row]}</td>`).join('')}<td>${row===0||row>=2?badge('P1','bad'):badge('Аттестован','good')}</td></tr>`).join('')}</tbody></table>`;
  }

  function accessDeniedPage(route) {
    const requirement = routeRequirement(route);
    const report = requirement.report ? reports[requirement.report] : null;
    return `${prototypeBanner()}${pageHead({eyebrow:badge('Доступ ограничен','bad'),title:'Рабочая область не разрешена',subtitle:'Интерфейс не полагается на скрытое меню: серверная проверка должна отклонить запрос к данным и действиям.'})}<section class="panel"><div class="empty-state"><div class="empty-icon">${icon('lock')}</div><div class="empty-title">${report ? `Отчёт «${report.title}» не назначен` : `Нет возможности ${requirement.capability || 'для этого маршрута'}`}</div><div class="empty-copy">Можно запросить конкретный отчёт или дополнительную возможность. Остальные пакеты пользователя останутся без изменений.</div><div style="margin-top:14px">${report ? button('Запросить доступ','key',{kind:'primary',attrs:`data-request-report="${report.id}"`}) : button('Открыть мой доступ','key',{kind:'primary',attrs:'data-route="access-user"'})}</div></div></section>`;
  }

  const routes = {
    workspace: workspacePage,
    reports: reportsPage,
    objects: objectsPage,
    entity: entityPage,
    problems: problemsPage,
    events: eventsPage,
    cases: casesPage,
    'ad-report': adReportPage,
    'gpo-report': gpoReportPage,
    'privileged-report': privilegedReportPage,
    'vpn-report': vpnReportPage,
    'project-readiness': projectReadinessPage,
    'access-center': accessCenterPage,
    'access-user': accessUserPage,
    'report-management': reportManagementPage,
    'report-editor': reportEditorPage
  };

  function parseHash() {
    const raw = location.hash.replace(/^#/, '');
    if (!raw) return { route: users[state.userId].defaultRoute, sub:'' };
    const [route, sub] = raw.split('/');
    return { route: routes[route] ? route : users[state.userId].defaultRoute, sub:sub || '' };
  }

  function renderPage() {
    renderChrome();
    const allowed = routeAllowed(state.route);
    $('#page').innerHTML = allowed ? routes[state.route]() : accessDeniedPage(state.route);
    renderNav();
    if (state.route === 'report-editor' && allowed) updateBuilderPreview();
    const heading = $('[data-page-heading]');
    document.title = `${heading?.textContent || 'SLI'} — универсальный прототип`;
    requestAnimationFrame(() => heading?.focus({ preventScroll:true }));
    window.scrollTo({ top:0, behavior:'instant' });
  }

  function navigate(route, sub = '') {
    if (!routes[route]) return;
    if (!routeAllowed(route)) {
      const requirement = routeRequirement(route);
      if (requirement.report) openRequestModal(requirement.report);
      else showToast('Доступ не разрешён', `Для раздела требуется возможность ${requirement.capability || 'из отдельного пакета'}.`);
      return;
    }
    state.route = route;
    if (route === 'entity' && sub) state.entityTab = sub;
    const hash = route === 'entity' ? `#entity/${state.entityTab}` : `#${route}`;
    if (location.hash !== hash) location.hash = hash;
    else renderPage();
    closeMobileMenu();
  }

  function switchUser(userId) {
    if (!users[userId]) return;
    state.userId = userId;
    safeSet('sli-v4-user', userId);
    state.entityTab = 'overview';
    state.route = users[userId].defaultRoute;
    const hash = `#${state.route}`;
    if (location.hash !== hash) location.hash = hash;
    else renderPage();
    showToast('Интерфейс пересобран', `Показан эффективный доступ пользователя ${users[userId].name}.`);
    closeMobileMenu();
  }

  function toggleTechnical() {
    state.technical = !state.technical;
    safeSet('sli-v4-technical', String(state.technical));
    renderChrome();
    showToast('Технический слой', state.technical ? 'Показаны дополнительные технические поля только там, где право уже выдано.' : 'Дополнительная техническая плотность скрыта; права не изменились.');
  }

  function showToast(title, copy) {
    const toast = document.createElement('div');
    toast.className = 'toast';
    toast.innerHTML = `<div class="toast-icon">${icon('info')}</div><div><div class="toast-title">${title}</div><div class="toast-copy">${copy}</div></div>`;
    $('#toast-region').append(toast);
    setTimeout(() => toast.remove(), 4500);
  }

  function openModal(html) {
    $('#modal').innerHTML = html;
    const scrim = $('#modal-scrim');
    scrim.classList.add('is-open');
    scrim.setAttribute('aria-hidden','false');
    requestAnimationFrame(() => $('input,select,button', $('#modal'))?.focus());
  }
  function closeModal() {
    const scrim = $('#modal-scrim');
    scrim.classList.remove('is-open');
    scrim.setAttribute('aria-hidden','true');
  }

  function openGrantModal(userId) {
    const user = users[userId];
    const unavailable = Object.values(reports).filter(r => !hasReport(r.id,userId));
    openModal(`<form id="grant-form" data-target-user="${userId}"><div class="modal-head"><div><h2 id="modal-title">Выдать доступ</h2><p>${user.name}: отчёт, уровень, область, поля и срок назначаются отдельно.</p></div><button class="icon-button" type="button" data-close-modal aria-label="Закрыть">${icon('close')}</button></div><div class="modal-body section-stack">
      <div class="grid two"><div class="field"><label>Отчёт или модуль</label><select name="reportId">${(unavailable.length ? unavailable : Object.values(reports)).map(r => `<option value="${r.id}">${r.title}</option>`).join('')}</select></div><div class="field"><label>Уровень</label><select name="level"><option>Просмотр</option><option selected>Анализ</option><option>Работа</option><option>Эксплуатация</option></select></div></div>
      <div class="grid two"><div class="field"><label>Область данных</label><select name="scope"><option>host5.example.invalid</option><option>OU=Users_KHV</option><option>OU=Новокузнецк</option><option>platform</option></select></div><div class="field"><label>Срок</label><select name="validity"><option value="31.12.2026">До 31.12.2026</option><option value="30.09.2026">До 30.09.2026</option><option value="Бессрочно">Бессрочно</option></select></div></div>
      <div class="field"><label>Дополнительные поля</label><select name="fields"><option>Без расширения полей</option><option>Контактные данные (pii.contact)</option><option>Кадровые данные (pii.hr)</option><option>Технические raw-поля</option></select></div>
      <div class="field"><label>Основание</label><textarea name="reason" required placeholder="Номер заявки, распоряжение, проект и цель доступа">Заявка SD-2026-4182 · участие в совместной проверке</textarea></div>
      <div class="callout warn">${icon('warning')}<div><div class="callout-title">Будет записано в аудит</div><div class="callout-copy">Автор, пользователь, отчёт, scope, срок, поля и основание. Бессрочный доступ требует отдельного подтверждения.</div></div></div>
    </div><div class="modal-footer">${button('Отмена','',{attrs:'data-close-modal'})}${button('Проверить и выдать','check',{kind:'primary',attrs:'type="submit"'})}</div></form>`);
  }

  function openRequestModal(reportId) {
    const r = reports[reportId];
    openModal(`<form id="request-form" data-report-id="${reportId}"><div class="modal-head"><div><h2 id="modal-title">Запросить доступ к отчёту</h2><p>${r.title}</p></div><button class="icon-button" type="button" data-close-modal>${icon('close')}</button></div><div class="modal-body section-stack"><div class="callout">${icon('report')}<div><div class="callout-title">${r.title}</div><div class="callout-copy">${r.description}</div></div></div><div class="field"><label>Нужная область данных</label><select><option>host5.example.invalid</option><option>OU=Users_KHV</option><option>Только мои объекты</option></select></div><div class="field"><label>Цель доступа</label><textarea required>Для выполнения назначенной проверки и перехода к карточкам объектов.</textarea></div><div class="field"><label>Желаемый срок</label><select><option>30 дней</option><option>До конца проекта</option><option>Бессрочно — требуется обоснование</option></select></div></div><div class="modal-footer">${button('Отмена','',{attrs:'data-close-modal'})}${button('Отправить запрос','key',{kind:'primary',attrs:'type="submit"'})}</div></form>`);
  }

  function openPublishModal(reportId) {
    const r = reports[reportId];
    openModal(`<form id="publish-form" data-report-id="${reportId}"><div class="modal-head"><div><h2 id="modal-title">Назначить отчёт</h2><p>${r.title}</p></div><button class="icon-button" type="button" data-close-modal>${icon('close')}</button></div><div class="modal-body section-stack"><div class="grid two"><div class="field"><label>Пользователь или группа</label><select name="subject"><option value="alex">Алексей Кузнецов</option><option value="marina">Марина Орлова</option><option value="dmitry">Дмитрий Соколов</option><option value="group:ad-auditors">Группа AD · аудит</option><option value="group:sec-analysts">Группа ИБ · аналитики</option></select></div><div class="field"><label>Уровень</label><select name="level"><option>Просмотр</option><option selected>Анализ</option><option>Работа</option></select></div></div><div class="grid two"><div class="field"><label>Область</label><select name="scope"><option>host5.example.invalid</option><option>OU=Users_KHV</option><option>platform</option></select></div><div class="field"><label>Срок</label><select name="validity"><option>31.12.2026</option><option>30.09.2026</option><option>Бессрочно</option></select></div></div><div class="field"><label>Основание публикации</label><textarea required>Плановая рабочая функция подразделения.</textarea></div></div><div class="modal-footer">${button('Отмена','',{attrs:'data-close-modal'})}${button('Назначить','check',{kind:'primary',attrs:'type="submit"'})}</div></form>`);
  }

  function openTraceDrawer(resourceId, userId = state.userId) {
    const access = effectiveAccess(userId);
    const user = users[userId];
    let title = resourceId;
    let sourceSteps = [];
    if (reports[resourceId]) {
      title = reports[resourceId].title;
      const grants = access.reportMap.get(resourceId) || [];
      sourceSteps = grants.map(g => ({ title:g.sourceType === 'direct' ? 'Прямое назначение' : 'Назначение через группу', copy:`${g.source} · уровень ${g.level} · scope ${g.scope} · срок ${g.validUntil}` }));
    } else {
      const groups = user.groups.filter(id => accessGroups[id].capabilities.includes(resourceId));
      sourceSteps = groups.map(id => ({ title:`Пакет ${accessGroups[id].label}`, copy:`Содержит возможность ${resourceId}` }));
    }
    $('#drawer-title').textContent = title;
    $('#drawer-body').innerHTML = `<div class="permission-trace"><div class="trace-step"><div class="trace-index">1</div><div><div class="trace-title">Субъект</div><div class="trace-copy">${user.name} · ${user.groups.length} пакета · ${user.directGrants.length} прямых назначений</div></div></div>${sourceSteps.map((step,i) => `<div class="trace-step"><div class="trace-index">${i+2}</div><div><div class="trace-title">${step.title}</div><div class="trace-copy">${step.copy}</div></div></div>`).join('')}<div class="trace-step"><div class="trace-index">${sourceSteps.length+2}</div><div><div class="trace-title">Серверная проверка</div><div class="trace-copy">Report/capability + область данных + поля + срок + явный запрет. Проверка выполняется при каждом запросе, а не только при построении меню.</div></div></div></div><section class="callout good" style="margin-top:16px">${icon('check')}<div><div class="callout-title">Итог: доступ разрешён</div><div class="callout-copy">Основание можно показать пользователю и аудитору без раскрытия внутренних секретов.</div></div></section>`;
    const scrim = $('#drawer-scrim');
    scrim.classList.add('is-open');
    scrim.setAttribute('aria-hidden','false');
  }

  function closeDrawer() {
    const scrim = $('#drawer-scrim');
    scrim.classList.remove('is-open');
    scrim.setAttribute('aria-hidden','true');
  }

  function openMobileMenu() { document.body.dataset.menuOpen = 'true'; }
  function closeMobileMenu() { document.body.dataset.menuOpen = 'false'; }

  document.addEventListener('click', event => {
    const routeEl = event.target.closest('[data-route]');
    if (routeEl) {
      const tab = routeEl.dataset.entityTab || '';
      navigate(routeEl.dataset.route, tab);
      return;
    }
    const tabEl = event.target.closest('[data-entity-tab]');
    if (tabEl) {
      state.entityTab = tabEl.dataset.entityTab;
      navigate('entity', state.entityTab);
      return;
    }
    const toastEl = event.target.closest('[data-toast-title]');
    if (toastEl) { showToast(toastEl.dataset.toastTitle, toastEl.dataset.toastCopy || 'Действие выполнено в прототипе.'); return; }
    const copyEl = event.target.closest('[data-copy]');
    if (copyEl) {
      navigator.clipboard?.writeText(copyEl.dataset.copy).catch(() => {});
      showToast('Скопировано', copyEl.dataset.copy);
      return;
    }
    const requestEl = event.target.closest('[data-request-report]');
    if (requestEl) { openRequestModal(requestEl.dataset.requestReport); return; }
    const capabilityEl = event.target.closest('[data-request-capability]');
    if (capabilityEl) { showToast('Нужна дополнительная возможность', `Запросите ${capabilityEl.dataset.requestCapability} у администратора доступа.`); return; }
    const grantEl = event.target.closest('[data-open-grant]');
    if (grantEl) { openGrantModal(grantEl.dataset.openGrant); return; }
    const publishEl = event.target.closest('[data-publish-report]');
    if (publishEl) { openPublishModal(publishEl.dataset.publishReport); return; }
    const traceEl = event.target.closest('[data-access-trace]');
    if (traceEl) { openTraceDrawer(traceEl.dataset.accessTrace, traceEl.dataset.traceUser || state.userId); return; }
    const selectUser = event.target.closest('[data-select-access-user]');
    if (selectUser) { state.selectedAccessUser = selectUser.dataset.selectAccessUser; navigate('access-user'); return; }
    const previewUser = event.target.closest('[data-preview-user]');
    if (previewUser) { switchUser(previewUser.dataset.previewUser); return; }
    const saveReport = event.target.closest('[data-save-report]');
    if (saveReport) {
      showToast(saveReport.dataset.saveReport === 'publish' ? 'Отчёт отправлен на публикацию' : 'Черновик сохранён', saveReport.dataset.saveReport === 'publish' ? 'Перед публикацией будут проверены поля, аудитория, scope и действия.' : 'Версия v0.1 сохранена без назначения аудитории.');
      return;
    }
    if (event.target.closest('[data-close-modal]')) { closeModal(); return; }
  });

  document.addEventListener('change', event => {
    if (event.target.id === 'demo-user') { switchUser(event.target.value); return; }
    if (event.target.id === 'report-filter') { state.reportFilter = event.target.value; renderPage(); return; }
    if (event.target.id === 'access-user-select') { state.selectedAccessUser = event.target.value; renderPage(); return; }
    if (event.target.matches('[data-builder-field]')) { updateBuilderPreview(); return; }
  });

  document.addEventListener('input', event => {
    if (event.target.id === 'report-search') {
      const q = event.target.value.trim().toLowerCase();
      $$('.report-card', $('#report-grid')).forEach(card => card.style.display = card.textContent.toLowerCase().includes(q) ? '' : 'none');
    }
    if (event.target.id === 'builder-title') {
      const title = event.target.value.trim() || 'Без названия';
      const preview = $('#builder-preview-title'); if (preview) preview.textContent = title;
    }
  });

  document.addEventListener('submit', event => {
    if (event.target.id === 'grant-form') {
      event.preventDefault();
      const form = new FormData(event.target);
      const userId = event.target.dataset.targetUser;
      const reportId = form.get('reportId');
      if (!users[userId].directGrants.some(g => g.reportId === reportId)) {
        users[userId].directGrants.push(directGrant(reportId, form.get('level'), form.get('scope'), form.get('reason'), form.get('validity')));
        if (!users[userId].pinned.includes(reportId)) users[userId].pinned.push(reportId);
      }
      closeModal();
      showToast('Доступ выдан', `${reports[reportId].title} назначен пользователю ${users[userId].name} до ${form.get('validity')}.`);
      renderPage();
      return;
    }
    if (event.target.id === 'request-form') {
      event.preventDefault();
      const reportId = event.target.dataset.reportId;
      closeModal();
      showToast('Запрос отправлен', `Администратор увидит отчёт «${reports[reportId].title}», scope, цель и срок.`);
      return;
    }
    if (event.target.id === 'publish-form') {
      event.preventDefault();
      const form = new FormData(event.target);
      const reportId = event.target.dataset.reportId;
      const subject = form.get('subject');
      if (!subject.startsWith('group:') && users[subject] && !users[subject].directGrants.some(g => g.reportId === reportId)) {
        users[subject].directGrants.push(directGrant(reportId, form.get('level'), form.get('scope'), 'Назначение из центра публикации', form.get('validity')));
      }
      closeModal();
      showToast('Отчёт назначен', `${reports[reportId].title}: ${subject.startsWith('group:') ? 'группа' : users[subject].name}, scope ${form.get('scope')}.`);
      renderPage();
    }
  });

  $('#technical-toggle').addEventListener('click', toggleTechnical);
  $('#mobile-menu').addEventListener('click', openMobileMenu);
  $('#mobile-scrim').addEventListener('click', closeMobileMenu);
  $('#drawer-close').addEventListener('click', closeDrawer);
  $('#drawer-scrim').addEventListener('click', event => { if (event.target === $('#drawer-scrim')) closeDrawer(); });
  $('#modal-scrim').addEventListener('click', event => { if (event.target === $('#modal-scrim')) closeModal(); });

  $('#global-search').addEventListener('keydown', event => {
    if (event.key === 'Enter') {
      const query = event.currentTarget.value.trim();
      if (can('entity.view') && /ivanov|иванов|corp\\/i.test(query)) navigate('entity','overview');
      else navigate('reports');
    }
  });

  document.addEventListener('keydown', event => {
    if ((event.ctrlKey || event.metaKey) && event.key.toLowerCase() === 'k') { event.preventDefault(); $('#global-search').focus(); }
    if (event.key === 'Escape') { closeModal(); closeDrawer(); closeMobileMenu(); }
  });

  window.addEventListener('hashchange', () => {
    const parsed = parseHash();
    state.route = parsed.route;
    if (parsed.route === 'entity' && parsed.sub) state.entityTab = parsed.sub;
    renderPage();
  });

  const initial = parseHash();
  state.route = initial.route;
  if (initial.route === 'entity' && initial.sub) state.entityTab = initial.sub;
  renderPage();
})();
