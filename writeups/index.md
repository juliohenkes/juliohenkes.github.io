---
layout: page
title: writeups
---

## writeups

<p class="section-desc">Machine writeups from Offensive Security Proving Grounds.</p>

{% for group in site.data.writeups %}
<span class="section-label">{{ group.difficulty }}</span>

<div class="wu-list">
{% for machine in group.machines %}<a href="{{ '/writeups/' | append: machine.slug | append: '/' | relative_url }}"><img src="{{ '/assets/icons/' | append: machine.os | append: '.svg' | relative_url }}" class="os-icon-sm" alt="{{ machine.os }}">{{ machine.name }}</a>
{% endfor %}</div>

{% endfor %}
