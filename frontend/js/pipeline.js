/**
 * pipeline.js — Scroll-triggered pipeline sequence (index.html only)
 *
 * One scroll-scrubbed progress value drives three things in lockstep:
 *  1. the WebGL camera flying the six-node rail (scene3d.js)
 *  2. the foreground SVG diagram (spine dash-offset + active node)
 *  3. the 2D stage-card grid's .active highlight
 *
 * Falls back to a time-based loop if GSAP/ScrollTrigger fail to load
 * (e.g. CDN blocked) so the section never looks frozen or broken.
 */
(function () {
  'use strict';

  var archEl = document.querySelector('.architecture');
  var spine = document.getElementById('flow-spine-progress');
  if (!archEl) return;

  var stageCards = Array.prototype.slice.call(document.querySelectorAll('.stage[data-stage]'));
  var flowNodes = Array.prototype.slice.call(document.querySelectorAll('.flow-node[data-stage]'));
  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
  var STAGES = Math.max(stageCards.length, flowNodes.length, 1);

  var spineLen = 0;
  if (spine) {
    try { spineLen = spine.getTotalLength(); } catch (e) { spineLen = 0; }
    spine.style.strokeDasharray = String(spineLen);
    spine.style.strokeDashoffset = String(spineLen);
  }

  function setProgress(p) {
    p = Math.max(0, Math.min(1, p));
    if (spine && spineLen) spine.style.strokeDashoffset = String(spineLen * (1 - p));

    var activeIdx = Math.min(STAGES - 1, Math.round(p * (STAGES - 1)));
    flowNodes.forEach(function (n, i) { n.classList.toggle('active', i <= activeIdx); });
    stageCards.forEach(function (c, i) { c.classList.toggle('active', i === activeIdx); });

    if (window.Scene3D && window.Scene3D.ready) window.Scene3D.setRailProgress(p);
  }

  function clearRail() {
    if (window.Scene3D && window.Scene3D.ready) window.Scene3D.setRailInactive();
  }

  function boot() {
    if (typeof gsap === 'undefined' || typeof ScrollTrigger === 'undefined') {
      fallbackLoop();
      return;
    }
    gsap.registerPlugin(ScrollTrigger);

    ScrollTrigger.create({
      trigger: archEl,
      start: 'top 88%',
      end: 'bottom 20%',
      scrub: reduceMotion ? true : 0.6,
      onUpdate: function (self) { setProgress(self.progress); },
      onLeave: clearRail,
      onLeaveBack: clearRail
    });
  }

  function fallbackLoop() {
    if (reduceMotion) { setProgress(1); return; }
    var idx = 0;
    setProgress(0);
    setInterval(function () {
      idx = (idx + 1) % STAGES;
      setProgress(idx / (STAGES - 1));
    }, 2600);
  }

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    boot();
  } else {
    document.addEventListener('DOMContentLoaded', boot);
  }
})();
