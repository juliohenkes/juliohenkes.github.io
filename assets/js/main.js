function toggleGroup(id) {
  var group = document.getElementById('group-' + id);
  if (group) group.classList.toggle('open');
}

window.addEventListener('pageshow', function(event) {
  if (event.persisted) {
    document.querySelectorAll('.sidebar-group').forEach(function(g) {
      g.classList.remove('open');
    });
    var active = document.querySelector('.sidebar-items a.active');
    if (active) {
      var parentGroup = active.closest('.sidebar-group');
      if (parentGroup) parentGroup.classList.add('open');
    }
  }
});
