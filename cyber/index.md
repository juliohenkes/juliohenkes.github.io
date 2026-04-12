---
layout: page
title: cyber
---

## cyber

<p class="section-desc">Pentest methodology, quick-reference toolkit, and machine writeups.</p>

{% for group in site.data.cyber %}
<span class="section-label">{{ group.group }}</span>

<div class="wu-list">
  {% for p in group.pages %}
  <a href="{{ '/cyber/' | append: group.group | append: '/' | append: p.slug | append: '/' | relative_url }}">{{ p.title }}</a>
  {% endfor %}
</div>
{% endfor %}

{% for group in site.data.writeups %}
<span class="section-label">writeups — {{ group.difficulty }}</span>

<div class="wu-list">
  {% for machine in group.machines %}
  <a href="{{ '/writeups/' | append: group.difficulty | append: '/' | append: machine.slug | append: '/' | relative_url }}">
    <img src="{{ '/assets/icons/' | append: machine.os | append: '.svg' | relative_url }}" class="os-icon-sm" alt="{{ machine.os }}">
    {{ machine.name }}
  </a>
  {% endfor %}
</div>
{% endfor %}
