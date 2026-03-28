// Sidebar toggles
document.querySelectorAll('.wu-group-toggle').forEach(function(btn) {
  var target = document.getElementById(btn.dataset.target);
  if (!target) return;
  btn.addEventListener('click', function() {
    var open = btn.getAttribute('aria-expanded') === 'true';
    btn.setAttribute('aria-expanded', String(!open));
    target.classList.toggle('closed', open);
  });
});

// Load markdown
var f = new URLSearchParams(window.location.search).get('f');
if (!f) return;

// Mark active link
document.querySelectorAll('.wu-list a').forEach(function(a) {
  if (a.getAttribute('href') === '?f=' + f) a.classList.add('active');
});

var diff  = f.split('/')[0];
var name  = f.split('/')[1] || '';

fetch(f + '.md')
  .then(function(r) { return r.text(); })
  .then(function(md) {
    var isWin    = md.indexOf('\uD83E\uDE9F') !== -1 || md.indexOf('🪟') !== -1;
    var osKey    = isWin ? 'windows' : 'linux';
    var osLabel  = isWin ? 'Windows' : 'Linux';
    var subMatch = md.match(/^> (.+)$/m);
    var subtitle = subMatch ? subMatch[1] : '';
    var diffLbl  = diff.charAt(0).toUpperCase() + diff.slice(1);

    var html = marked.parse(md);
    html = html.replace(/<h1[^>]*>[\s\S]*?<\/h1>\n?/, '');

    document.getElementById('wu-content').innerHTML =
      '<article class="wu-article">' +
        '<h1>' + name + '</h1>' +
        '<div class="wu-meta">' +
          '<span class="wu-badge ' + diff + '">' + diffLbl + '</span>' +
          '<span class="wu-os"><img src="../assets/icons/' + osKey + '.svg" class="os-icon" alt="' + osLabel + '"> ' + osLabel + '</span>' +
          (subtitle ? '<span class="wu-subtitle">// ' + subtitle + '</span>' : '') +
        '</div>' +
        '<div class="wu-body">' + html + '</div>' +
      '</article>';

    document.title = name + ' — writeups';
  })
  .catch(function(e) {
    document.getElementById('wu-content').innerHTML =
      '<p style="color:#ff4444;font-family:monospace;padding:40px">erro ao carregar: ' + f + '.md</p>';
  });
