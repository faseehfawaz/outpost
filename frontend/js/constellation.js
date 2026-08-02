/**
 * constellation.js — Scroll-scrubbed camera for the Live Threat
 * Constellation section (index.html only).
 *
 * Continues the pipeline rail's camera path: as the user scrolls through
 * #constellation, a single progress value flies the WebGL camera deeper
 * into the live-node "solar system" built from real /api/feeds/live data
 * (see scene3d.js's constellation* functions and app.js's loadLive()).
 * Falls back to a static mid-reveal if GSAP/ScrollTrigger fail to load,
 * so the section never looks frozen or broken.
 */
(function () {
  'use strict';

  var sectionEl = document.getElementById('constellation');
  var stageEl = document.getElementById('constellation-stage');
  if (!sectionEl || !stageEl) return;

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function setProgress(p) {
    p = Math.max(0, Math.min(1, p));
    if (window.Scene3D && window.Scene3D.ready) window.Scene3D.setConstellationProgress(p);
  }

  function clearFocus() {
    if (window.Scene3D && window.Scene3D.ready) window.Scene3D.setConstellationInactive();
  }

  function boot() {
    if (typeof gsap === 'undefined' || typeof ScrollTrigger === 'undefined') {
      setProgress(reduceMotion ? 1 : 0.5);
      return;
    }
    gsap.registerPlugin(ScrollTrigger);

    ScrollTrigger.create({
      trigger: sectionEl,
      start: 'top 75%',
      end: 'bottom 25%',
      scrub: reduceMotion ? true : 0.7,
      onUpdate: function (self) { setProgress(self.progress); },
      onLeave: clearFocus,
      onLeaveBack: clearFocus
    });
  }

  if (document.readyState === 'complete' || document.readyState === 'interactive') {
    boot();
  } else {
    document.addEventListener('DOMContentLoaded', boot);
  }
})();
