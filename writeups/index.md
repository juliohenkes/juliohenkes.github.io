---
layout: page
title: writeups
description: "Machine writeups from Offensive Security Proving Grounds — easy, intermediate, and hard boxes."
---

<header class="section-hero">
  <div class="section-kicker">archive · 03</div>
  <h1 class="section-title">Machine <em>writeups</em></h1>
  <p class="section-lede">
    Offensive Security Proving Grounds reports. Each entry walks the kill chain from
    reconnaissance to administrator — short prose, real commands.
  </p>
</header>

{% for group in site.data.writeups %}
<section class="section-group diff-section {{ group.difficulty }}">
  <h2 class="section-group-label" data-num="{{ forloop.index | prepend: '0' | slice: -2, 2 }}">{{ group.difficulty }} · {{ group.machines | size }} boxes</h2>
  <div class="entry-list">
    {% for machine in group.machines %}
    <a href="{{ '/writeups/' | append: machine.slug | append: '/' | relative_url }}">
      <span class="idx">{{ forloop.index | prepend: '00' | slice: -2, 2 }}</span>
      <span><img src="{{ '/assets/icons/' | append: machine.os | append: '.svg' | relative_url }}" class="os-icon-sm" alt="{{ machine.os }}"> {{ machine.name }}</span>
      <span class="arrow">→</span>
    </a>
    {% endfor %}
  </div>
</section>
{% endfor %}
