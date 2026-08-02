/**
 * takedownflow.js — Scroll-scrubbed camera for the Takedown Flow section
 * (index.html only).
 *
 * Continues the camera path from the Live Threat Constellation: as the user
 * scrolls through #takedownflow, a single progress value flies the WebGL
 * camera into the dispatch-hub view built from real /api/feeds/takedowns
 * data (see scene3d.js's takedown* functions and app.js's loadTakedowns()).
 * Falls back to a static mid-reveal if GSAP/ScrollTrigger fail to load,
 * so the section never looks frozen or broken.
 */
(function () {
  'use strict';

  var sectionEl = document.getElementById('takedownflow');
  var stageEl = document.getElementById('takedownflow-stage');
  if (!sectionEl || !stageEl) return;

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  function setProgress(p) {
    p = Math.max(0, Math.min(1, p));
    if (window.Scene3D && window.Scene3D.ready) window.Scene3D.setTakedownProgress(p);
  }

  function clearFocus() {
    if (window.Scene3D && window.Scene3D.ready) window.Scene3D.setTakedownInactive();
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
