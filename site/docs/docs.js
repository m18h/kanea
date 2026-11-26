// Navigation for the docs pages. Every page in site/docs/ loads this file.
//
// PAGES below is the single source of the nav: the sidebar, the Previous/Next
// links at the foot of a page and their order all come from it. To add a page,
// add a row here; no page carries a hand-written list of the others. A row
// with head: true is its group's own page: the group heading links to it.
//
// What it does, in order:
//   1. On index.html, sends an old single-page anchor (index.html#spec-task)
//      to the page that section moved to.
//   2. Renders the sidebar: groups, pages, and the current page's h2 sections.
//   3. Appends the Previous/Next links.
//   4. Marks the section being read, and lets the contents collapse on a
//      narrow screen.
(function () {
  var PAGES = [
    { group: null, file: 'index.html', title: 'Documentation' },
    { group: 'Get started', file: 'get-started.html', title: 'Get started', head: true },
    { group: 'Get started', file: 'install.html', title: 'Install a node' },
    { group: 'Get started', file: 'first-service.html', title: 'Deploy your first service' },
    { group: 'Get started', file: 'concepts.html', title: 'Concepts' },
    { group: 'Guides', file: 'domains.html', title: 'Domains and HTTPS' },
    { group: 'Guides', file: 'secrets.html', title: 'Secrets' },
    { group: 'Guides', file: 'volumes.html', title: 'Volumes and host access' },
    { group: 'Guides', file: 'backups.html', title: 'Back up a node' },
    { group: 'Guides', file: 'auth.html', title: 'Sign-in and access' },
    { group: 'Guides', file: 'dashboard.html', title: 'The dashboard' },
    { group: 'Guides', file: 'remote.html', title: 'Remote nodes and CI' },
    { group: 'Guides', file: 'mcp.html', title: 'AI agents (MCP)' },
    { group: 'Guides', file: 'upgrade.html', title: 'Upgrade and uninstall' },
    { group: 'Guides', file: 'stacks.html', title: 'Sample stacks' },
    { group: 'Guides', file: 'troubleshooting.html', title: 'Troubleshooting' },
    { group: 'Reference', file: 'node-config.html', title: 'Node config (kanea.hcl)' },
    { group: 'Reference', file: 'spec.html', title: 'Spec reference' },
    { group: 'Reference', file: 'cli.html', title: 'CLI reference' },
    { group: 'Internals', file: 'architecture.html', title: 'Architecture' }
  ];

  // Old single-page anchors, by id prefix. First match wins, so the specific
  // entries sit above the part they belong to.
  var REDIRECTS = [
    ['overview-first', 'first-service.html'],
    ['overview-secrets', 'secrets.html'],
    ['overview', 'concepts.html'],
    ['install-upgrade', 'upgrade.html'],
    ['install', 'install.html'],
    ['arch-dashboard', 'dashboard.html'],
    ['arch', 'architecture.html'],
    ['nodeconfig', 'node-config.html'],
    ['dns', 'domains.html'],
    ['spec', 'spec.html'],
    ['stacks', 'stacks.html'],
    ['cli', 'cli.html'],
    ['mcp', 'mcp.html'],
    ['remote', 'remote.html'],
    ['troubleshoot', 'troubleshooting.html']
  ];

  var REPOSITORY = [
    ['https://github.com/m18h/kanea/blob/main/PRD.md', 'PRD.md'],
    ['https://github.com/m18h/kanea/blob/main/docs/THREAT_MODEL.md', 'Threat model'],
    ['https://github.com/m18h/kanea/blob/main/docs/DR_RUNBOOK.md', 'DR runbook']
  ];

  // A path ending in "/" (or naming no .html file) is the index.
  var here = location.pathname.split('/').pop();
  if (!/\.html$/.test(here)) here = 'index.html';

  if (here === 'index.html' && location.hash.length > 1) {
    var id = location.hash.slice(1);
    try { id = decodeURIComponent(id); } catch (e) { /* keep the raw id */ }
    // An id this page defines itself is never an old anchor.
    if (!document.getElementById(id)) {
      for (var r = 0; r < REDIRECTS.length; r++) {
        if (id.indexOf(REDIRECTS[r][0]) === 0) {
          location.replace(REDIRECTS[r][1] + location.hash);
          return;
        }
      }
    }
  }

  var list = document.getElementById('toc-list');
  var main = document.querySelector('main.prose');
  if (!list || !main) return;

  function el(tag, text) {
    var node = document.createElement(tag);
    if (text != null) node.textContent = text;
    return node;
  }
  function link(cls, href, text) {
    var a = el('a', text);
    if (cls) a.className = cls;
    a.setAttribute('href', href);
    return a;
  }

  // ---- sidebar ----
  var targets = Array.prototype.slice.call(main.querySelectorAll('h2[id]'));
  var byId = {};
  var frag = document.createDocumentFragment();
  var group = null, index = -1;

  PAGES.forEach(function (page, i) {
    var a;
    if (page.head) {
      a = link('', page.file, page.title);
      frag.appendChild(el('h4')).appendChild(a);
    } else {
      if (page.group && page.group !== group) frag.appendChild(el('h4', page.group));
      a = link('part', page.file, page.title);
      frag.appendChild(a);
    }
    group = page.group;
    if (page.file !== here) return;
    index = i;
    a.setAttribute('aria-current', 'page');
    if (!targets.length) return;
    var subs = el('div');
    subs.className = 'subs';
    targets.forEach(function (h) {
      byId[h.id] = subs.appendChild(link('', '#' + h.id, h.textContent));
    });
    frag.appendChild(subs);
  });

  frag.appendChild(el('h4', 'Repository'));
  REPOSITORY.forEach(function (repo) {
    frag.appendChild(link('ext', repo[0], repo[1] + '\u00a0\u2197'));
  });

  list.textContent = '';
  list.appendChild(frag);

  // The list can be longer than its panel. Start with the page being read
  // near the top, so its sections show below it rather than off the bottom.
  var open = list.querySelector('[aria-current="page"]');
  if (open && list.scrollHeight > list.clientHeight) {
    list.scrollTop = Math.max(0, open.offsetTop - 80);
  }

  // ---- previous / next ----
  if (index >= 0) {
    var pagenav = el('nav');
    pagenav.className = 'pagenav';
    pagenav.setAttribute('aria-label', 'Previous and next page');
    [[index - 1, 'Previous'], [index + 1, 'Next']].forEach(function (step) {
      var page = PAGES[step[0]];
      if (!page) return;
      var a = el('a');
      a.setAttribute('href', page.file);
      a.appendChild(el('small', step[1]));
      a.appendChild(el('b', page.title));
      pagenav.appendChild(a);
    });
    main.appendChild(pagenav);
  }

  // ---- mark the section being read ----
  // Only section links are marked here. The page link keeps its own
  // aria-current="page" and is never touched.
  var current = null;
  function mark(a) {
    if (!a || a === current) return;
    if (current) current.removeAttribute('aria-current');
    current = a;
    current.setAttribute('aria-current', 'true');
    // Keep the marked entry inside the scrolled contents panel.
    var top = current.offsetTop, h = list.clientHeight;
    if (top < list.scrollTop || top > list.scrollTop + h - 40) {
      list.scrollTop = Math.max(0, top - h / 2);
    }
  }

  // The heading nearest the top of the viewport wins. An IntersectionObserver
  // alone reports whatever crosses the boundary, which flickers between two
  // headings when a short section scrolls past; this picks deterministically.
  // The threshold matches the sticky chrome (header alone on desktop, header
  // plus the contents bar on mobile) so the mark agrees with where a jump lands.
  function update() {
    var offset = matchMedia('(max-width: 900px)').matches ? 140 : 90;
    var best = null, bestTop = -Infinity;
    for (var i = 0; i < targets.length; i++) {
      var t = targets[i].getBoundingClientRect().top - offset;
      if (t <= 0 && t > bestTop) { bestTop = t; best = targets[i]; }
    }
    if (!best && targets.length) best = targets[0];
    if (best) mark(byId[best.id]);
  }

  var ticking = false;
  addEventListener('scroll', function () {
    if (ticking) return;
    ticking = true;
    requestAnimationFrame(function () { update(); ticking = false; });
  }, { passive: true });
  addEventListener('resize', update, { passive: true });
  update();

  // ---- collapse the contents on a narrow screen ----
  var toc = document.getElementById('toc');
  var toggle = document.querySelector('.toc-toggle');
  if (!toc || !toggle) return;
  toggle.addEventListener('click', function () {
    var open = toggle.getAttribute('aria-expanded') === 'true';
    toggle.setAttribute('aria-expanded', String(!open));
    toc.classList.toggle('open', !open);
  });
  list.addEventListener('click', function (e) {
    if (e.target.tagName === 'A' && matchMedia('(max-width: 900px)').matches) {
      toggle.setAttribute('aria-expanded', 'false');
      toc.classList.remove('open');
    }
  });
})();
