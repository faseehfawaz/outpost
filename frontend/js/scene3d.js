/**
 * scene3d.js — Outpost 3D Engine (Three.js r128)
 * Outpost · heapleap suite
 *
 * One persistent full-viewport WebGL scene shared by every page. It renders,
 * depending on what a given page opts into:
 *
 *   CORE          a wireframe geodesic core + orbit rings, the site's
 *                 persistent visual signature (every page).
 *   FIELD         the ambient particle field + link mesh (every page,
 *                 unchanged from the original build).
 *   RAIL          the six-node pipeline flythrough, scroll-scrubbed by
 *                 pipeline.js (index.html only, unchanged behavior).
 *   CONSTELLATION real, live data — every currently-live phishing URL from
 *                 /api/feeds/live rendered as an orbiting node, colored by
 *                 score, connected to a central sun by a pulse arc. Nodes
 *                 spawn/despawn as the underlying data changes. Scroll-
 *                 scrubbed by constellation.js (index.html only).
 *   ACTOR GRAPH   real actor records from /api/actors laid out with a small
 *                 in-browser force simulation, sized by kit_count, colored
 *                 by recency, edged by shared targeted brands (actors.html).
 *   DATA STREAM   real redacted IOC records from /api/ioc arranged in a
 *                 drifting helical tunnel (ioc.html).
 *
 * Every one of these is picked from real API data passed in by app.js /
 * actors.js / ioc.js — nothing here fabricates threat data. Empty data
 * renders an idle/ambient state, never invented nodes.
 *
 * Interactivity: dedicated "stage" elements (#constellation-stage,
 * #actorgraph-stage, #datastream-stage) get raycast hover/click (dispatched
 * as window CustomEvents so the page-specific script can react — flashing a
 * table row, opening the existing actor modal, filtering the IOC table) and
 * a hand-rolled drag-to-orbit camera control with release inertia.
 *
 * Everything is additive: if WebGL is unavailable, every method below is a
 * no-op stub and the page renders exactly as it would with no JS 3D layer.
 * `prefers-reduced-motion` disables continuous motion (rotation, drift,
 * spawn easing, inertia) but real data is still shown, just settled/static.
 */
(function () {
  'use strict';

  var canvas = document.getElementById('bg-canvas');
  if (!canvas) { window.Scene3D = stub(); return; }

  function supportsWebGL() {
    try {
      var c = document.createElement('canvas');
      return !!(window.WebGLRenderingContext &&
        (c.getContext('webgl') || c.getContext('experimental-webgl')));
    } catch (e) { return false; }
  }

  function stub() {
    return {
      isSupported: false, ready: false,
      init: function () {}, setRailProgress: function () {},
      setRailInactive: function () {}, setActiveStage: function () {},
      setConstellationData: function () {}, setConstellationProgress: function () {},
      setConstellationInactive: function () {},
      setActorGraphData: function () {}, setActorGraphActive: function () {},
      setDataStreamData: function () {}, setDataStreamActive: function () {},
      setTakedownFlowData: function () {}, setTakedownProgress: function () {}, setTakedownInactive: function () {}
    };
  }

  if (typeof THREE === 'undefined' || !supportsWebGL()) {
    document.documentElement.classList.add('no-webgl');
    window.Scene3D = stub();
    return;
  }

  var reduceMotion = window.matchMedia('(prefers-reduced-motion: reduce)').matches;

  // ---- palette — mirrors css/style.css :root tokens exactly ----
  var COLOR = {
    signal: 0x39ff88,
    intel: 0x5eebff,
    amber: 0xffb84d,
    danger: 0xff4d6d,
    violet: 0xa78bfa,
    muted: 0x8fa0a3,
    voidColor: 0x050607
  };

  // ============================================================
  // TINY HELPERS (no THREE.MathUtils dependency — keep r128-safe)
  // ============================================================
  function lerp(a, b, n) { return a + (b - a) * n; }
  function clamp(v, min, max) { return Math.max(min, Math.min(max, v)); }

  function hashStr(str) {
    var h = 2166136261;
    for (var i = 0; i < str.length; i++) {
      h ^= str.charCodeAt(i);
      h = (h * 16777619) >>> 0;
    }
    return h >>> 0;
  }
  function hashUnit(str, salt) {
    return (hashStr(str + '|' + salt) % 100000) / 100000; // deterministic 0..1
  }

  function quadPoints(p0, p1, p2, segments) {
    var pts = new Float32Array((segments + 1) * 3);
    for (var i = 0; i <= segments; i++) {
      var t = i / segments, mt = 1 - t;
      pts[i * 3] = mt * mt * p0.x + 2 * mt * t * p1.x + t * t * p2.x;
      pts[i * 3 + 1] = mt * mt * p0.y + 2 * mt * t * p1.y + t * t * p2.y;
      pts[i * 3 + 2] = mt * mt * p0.z + 2 * mt * t * p1.z + t * t * p2.z;
    }
    return pts;
  }

  function disposeSprite(sprite) {
    if (sprite.parent) sprite.parent.remove(sprite);
    if (sprite.material) sprite.material.dispose();
  }
  function disposeLine(line) {
    if (line.parent) line.parent.remove(line);
    if (line.geometry) line.geometry.dispose();
    if (line.material) line.material.dispose();
  }

  // ============================================================
  // MODULE STATE
  // ============================================================
  var renderer, scene, camera, clock;
  var sharedGlow;
  var fieldGroup, fieldGeo, fieldMat, positions, colors, velocities, FIELD_COUNT = 0;
  var linkGeo, linkPositions, linkColors, linkMat, MAX_LINKS = 130;

  var railCurve = null, stageSprites = [], railLine = null;
  var NODE_T_START = 0.2, NODE_T_END = 0.86, STAGE_COUNT = 6;
  var railActive = false, activeStageIndex = -1;

  var coreGroup, coreWire, coreInner, coreRing1, coreRing2, coreParts = [];

  var constellationGroup, constellationArcsGroup, constellationSun, constellationNodes;
  var constellationInteractive = [];
  var constellationActive = false, constellationExtraSpin = 0;
  var CONSTELLATION_Z = -1040;
  var CONST_CAM_START, CONST_CAM_END, CONST_LOOK_START, CONST_LOOK_END;

  var actorGraphGroup, actorGraphEdges = null;
  var actorGraphInteractive = [], actorGraphActive = false, actorGraphBuilt = false;
  var ACTORGRAPH_CAM;

  var streamGroup, streamTiles = [], streamInteractive = [];
  var streamActive = false, streamBuilt = false;
  var STREAM_CAM;
  var STREAM_KIND_COLOR;

  var takedownGroup, takedownHub, takedownTargets = {}, takedownInteractive = [];
  var takedownActive = false, takedownBuilt = false;
  var seenTakedownIds = null; // null = "never loaded" (first-load heuristic)
  var TAKEDOWN_Z = -1300;
  var TAKEDOWN_CAM_START, TAKEDOWN_CAM_END, TAKEDOWN_LOOK_START, TAKEDOWN_LOOK_END;
  var TARGET_TYPE_COLOR_RULES = [
    [/registr/, 0x5eebff /* intel */],
    [/host/, 0xffb84d /* amber */],
    [/telegram|discord/, 0xa78bfa /* violet */],
    [/safe|apwg|platform|google/, 0xff4d6d /* danger */]
  ];

  var desiredPos = null, desiredLook = null;
  var focusMode = 'idle'; // idle | rail | constellation | actorgraph | datastream | takedownflow
  var mouseNX = 0, mouseNY = 0;
  var running = true, initialized = false, frameCount = 0;
  var _tmpCamTarget, _tmpLookTarget;

  // drag-to-orbit
  var raycaster, ndc;
  var hoveredObject = null;
  var dragging = false, dragMoved = false, dragLastX = 0, dragLastY = 0;
  var dragYaw = 0, dragPitch = 0, dragVelYaw = 0, dragVelPitch = 0;
  var _sph, _dir, _orbitPos;
  var EMPTY_ARR = [];

  function maybeIdle() {
    if (!railActive && !constellationActive && !actorGraphActive && !streamActive && !takedownActive) {
      focusMode = 'idle';
    }
  }

  // ============================================================
  // TEXTURES
  // ============================================================
  function makeGlowTexture() {
    var size = 128;
    var c = document.createElement('canvas');
    c.width = c.height = size;
    var ctx = c.getContext('2d');
    var g = ctx.createRadialGradient(size / 2, size / 2, 0, size / 2, size / 2, size / 2);
    g.addColorStop(0, 'rgba(255,255,255,1)');
    g.addColorStop(0.35, 'rgba(255,255,255,.65)');
    g.addColorStop(1, 'rgba(255,255,255,0)');
    ctx.fillStyle = g;
    ctx.fillRect(0, 0, size, size);
    return new THREE.CanvasTexture(c);
  }

  function wrapText(ctx, text, x, y, maxWidth, lineHeight, maxLines) {
    var raw = String(text || '');
    var lines = [], line = '';
    for (var i = 0; i < raw.length; i++) {
      var test = line + raw[i];
      if (ctx.measureText(test).width > maxWidth && line) {
        lines.push(line);
        line = raw[i];
        if (lines.length >= maxLines) { line = ''; break; }
      } else {
        line = test;
      }
    }
    if (line && lines.length < maxLines) lines.push(line);
    lines.slice(0, maxLines).forEach(function (l, i2) { ctx.fillText(l, x, y + i2 * lineHeight); });
  }

  function makeLabelTexture(kind, valueText, subText) {
    var w = 320, h = 152;
    var c = document.createElement('canvas');
    c.width = w; c.height = h;
    var ctx = c.getContext('2d');
    var kindColor = '#' + new THREE.Color(STREAM_KIND_COLOR[kind] || COLOR.intel).getHexString();

    ctx.fillStyle = 'rgba(8,10,11,0.86)';
    ctx.fillRect(0, 0, w, h);
    ctx.strokeStyle = kindColor;
    ctx.lineWidth = 3;
    ctx.strokeRect(1.5, 1.5, w - 3, h - 3);
    ctx.fillStyle = kindColor;
    ctx.fillRect(1.5, 1.5, w - 3, 5);

    ctx.fillStyle = kindColor;
    ctx.font = '600 19px "IBM Plex Mono", monospace';
    ctx.fillText(String(kind || 'ioc').toUpperCase(), 16, 38);

    ctx.fillStyle = '#e9edef';
    ctx.font = '15px "IBM Plex Mono", monospace';
    wrapText(ctx, valueText, 16, 68, w - 32, 19, 3);

    ctx.fillStyle = '#8fa0a3';
    ctx.font = '12px "IBM Plex Mono", monospace';
    wrapText(ctx, subText, 16, h - 16, w - 32, 14, 1);

    var tex = new THREE.CanvasTexture(c);
    tex.needsUpdate = true;
    return tex;
  }

  // ============================================================
  // AMBIENT FIELD (unchanged behavior from the original build)
  // ============================================================
  function buildField(glowTex) {
    FIELD_COUNT = window.innerWidth < 760 ? 260 : 520;
    fieldGroup = new THREE.Group();
    scene.add(fieldGroup);

    positions = new Float32Array(FIELD_COUNT * 3);
    colors = new Float32Array(FIELD_COUNT * 3);
    velocities = [];

    var palette = [COLOR.signal, COLOR.intel, COLOR.intel, COLOR.amber];
    var tmpColor = new THREE.Color();

    for (var i = 0; i < FIELD_COUNT; i++) {
      var radius = 50 + Math.random() * 260;
      var theta = Math.random() * Math.PI * 2;
      positions[i * 3] = radius * Math.cos(theta) * (0.4 + Math.random() * 0.6);
      positions[i * 3 + 1] = (Math.random() - 0.5) * 220;
      positions[i * 3 + 2] = -Math.random() * 940 + 90;

      tmpColor.setHex(palette[Math.floor(Math.random() * palette.length)]);
      colors[i * 3] = tmpColor.r; colors[i * 3 + 1] = tmpColor.g; colors[i * 3 + 2] = tmpColor.b;

      velocities.push({
        x: (Math.random() - 0.5) * 0.025,
        y: (Math.random() - 0.5) * 0.02,
        z: (Math.random() - 0.5) * 0.03
      });
    }

    fieldGeo = new THREE.BufferGeometry();
    fieldGeo.setAttribute('position', new THREE.BufferAttribute(positions, 3));
    fieldGeo.setAttribute('color', new THREE.BufferAttribute(colors, 3));

    fieldMat = new THREE.PointsMaterial({
      size: 3.2,
      map: glowTex,
      vertexColors: true,
      transparent: true,
      opacity: 0.8,
      depthWrite: false,
      blending: THREE.AdditiveBlending,
      sizeAttenuation: true
    });
    fieldGroup.add(new THREE.Points(fieldGeo, fieldMat));

    linkPositions = new Float32Array(MAX_LINKS * 2 * 3);
    linkColors = new Float32Array(MAX_LINKS * 2 * 3);
    linkGeo = new THREE.BufferGeometry();
    linkGeo.setAttribute('position', new THREE.BufferAttribute(linkPositions, 3));
    linkGeo.setAttribute('color', new THREE.BufferAttribute(linkColors, 3));
    linkGeo.setDrawRange(0, 0);
    linkMat = new THREE.LineBasicMaterial({
      vertexColors: true, transparent: true, opacity: 0.2,
      blending: THREE.AdditiveBlending, depthWrite: false
    });
    fieldGroup.add(new THREE.LineSegments(linkGeo, linkMat));
  }

  function rebuildLinks() {
    if (!linkGeo) return;
    var count = 0;
    var maxDistSq = 42 * 42;
    for (var i = 0; i < FIELD_COUNT && count < MAX_LINKS; i++) {
      for (var j = i + 1; j < FIELD_COUNT && count < MAX_LINKS; j += 7) {
        var dx = positions[i * 3] - positions[j * 3];
        var dy = positions[i * 3 + 1] - positions[j * 3 + 1];
        var dz = positions[i * 3 + 2] - positions[j * 3 + 2];
        var d2 = dx * dx + dy * dy + dz * dz;
        if (d2 < maxDistSq) {
          var pb = count * 6;
          linkPositions[pb] = positions[i * 3]; linkPositions[pb + 1] = positions[i * 3 + 1]; linkPositions[pb + 2] = positions[i * 3 + 2];
          linkPositions[pb + 3] = positions[j * 3]; linkPositions[pb + 4] = positions[j * 3 + 1]; linkPositions[pb + 5] = positions[j * 3 + 2];
          linkColors[pb] = colors[i * 3]; linkColors[pb + 1] = colors[i * 3 + 1]; linkColors[pb + 2] = colors[i * 3 + 2];
          linkColors[pb + 3] = colors[j * 3]; linkColors[pb + 4] = colors[j * 3 + 1]; linkColors[pb + 5] = colors[j * 3 + 2];
          count++;
        }
      }
    }
    linkGeo.setDrawRange(0, count * 2);
    linkGeo.attributes.position.needsUpdate = true;
    linkGeo.attributes.color.needsUpdate = true;
  }

  function updateField() {
    if (reduceMotion) return;
    for (var i = 0; i < FIELD_COUNT; i++) {
      var v = velocities[i];
      positions[i * 3] += v.x; positions[i * 3 + 1] += v.y; positions[i * 3 + 2] += v.z;
      if (Math.abs(positions[i * 3]) > 320) v.x *= -1;
      if (Math.abs(positions[i * 3 + 1]) > 240) v.y *= -1;
      if (positions[i * 3 + 2] > 120 || positions[i * 3 + 2] < -900) v.z *= -1;
    }
    fieldGeo.attributes.position.needsUpdate = true;
  }

  // ============================================================
  // CORE — the persistent "Outpost Core": wireframe geodesic +
  // two tilted orbit rings + pulsing inner light. Present on every
  // page as the brand signature; dims (never disappears) whenever
  // a page-specific data mode takes focus.
  // ============================================================
  function buildCore(glowTex) {
    coreGroup = new THREE.Group();
    scene.add(coreGroup);

    var wireMat = new THREE.LineBasicMaterial({ color: COLOR.intel, transparent: true, opacity: 0.22 });
    coreWire = new THREE.LineSegments(new THREE.WireframeGeometry(new THREE.IcosahedronGeometry(20, 1)), wireMat);
    coreGroup.add(coreWire);
    coreParts.push({ mat: wireMat, base: 0.22 });

    var innerMat = new THREE.MeshBasicMaterial({ color: COLOR.signal, transparent: true, opacity: 0.85 });
    coreInner = new THREE.Mesh(new THREE.SphereGeometry(5, 20, 20), innerMat);
    coreGroup.add(coreInner);
    coreParts.push({ mat: innerMat, base: 0.85 });

    var ring1Mat = new THREE.MeshBasicMaterial({ color: COLOR.intel, transparent: true, opacity: 0.22, side: THREE.DoubleSide });
    coreRing1 = new THREE.Mesh(new THREE.TorusGeometry(34, 0.35, 8, 84), ring1Mat);
    coreRing1.rotation.x = Math.PI / 2.4;
    coreGroup.add(coreRing1);
    coreParts.push({ mat: ring1Mat, base: 0.22 });

    var ring2Mat = new THREE.MeshBasicMaterial({ color: COLOR.amber, transparent: true, opacity: 0.16, side: THREE.DoubleSide });
    coreRing2 = new THREE.Mesh(new THREE.TorusGeometry(45, 0.28, 8, 84), ring2Mat);
    coreRing2.rotation.x = Math.PI / 1.7;
    coreRing2.rotation.y = 0.4;
    coreGroup.add(coreRing2);
    coreParts.push({ mat: ring2Mat, base: 0.16 });

    var haloMat = new THREE.SpriteMaterial({ map: glowTex, color: COLOR.signal, transparent: true, opacity: 0.55, blending: THREE.AdditiveBlending, depthWrite: false });
    var halo = new THREE.Sprite(haloMat);
    halo.scale.set(30, 30, 1);
    coreGroup.add(halo);
    coreParts.push({ mat: haloMat, base: 0.55 });
  }

  function updateCore(t) {
    if (!coreGroup) return;
    if (!reduceMotion) {
      coreWire.rotation.y = t * 0.06;
      coreWire.rotation.x = t * 0.015;
      coreRing1.rotation.z = t * 0.05;
      coreRing2.rotation.z = -t * 0.035;
      coreInner.scale.setScalar(1 + Math.sin(t * 1.6) * 0.1);
    }
    var factor = focusMode === 'idle' ? 1 : 0.2;
    coreParts.forEach(function (p) {
      p.mat.opacity += (p.base * factor - p.mat.opacity) * 0.05;
    });
  }

  // ============================================================
  // RAIL — six-node pipeline flythrough (unchanged from original;
  // pipeline.js depends on this exact API surface).
  // ============================================================
  function buildRail(glowTex) {
    var waypoints = [
      new THREE.Vector3(0, 8, 110),
      new THREE.Vector3(-26, 4, -10),
      new THREE.Vector3(-52, -6, -130),
      new THREE.Vector3(-20, 8, -260),
      new THREE.Vector3(20, -6, -390),
      new THREE.Vector3(50, 6, -520),
      new THREE.Vector3(24, -8, -650),
      new THREE.Vector3(-8, 4, -770),
      new THREE.Vector3(0, 0, -900)
    ];
    railCurve = new THREE.CatmullRomCurve3(waypoints, false, 'catmullrom', 0.4);

    var railPts = railCurve.getPoints(90);
    var rGeo = new THREE.BufferGeometry().setFromPoints(railPts);
    var rMat = new THREE.LineBasicMaterial({ color: COLOR.intel, transparent: true, opacity: 0.14 });
    railLine = new THREE.Line(rGeo, rMat);
    scene.add(railLine);

    var stageColors = [COLOR.signal, COLOR.intel, COLOR.intel, COLOR.amber, COLOR.amber, COLOR.signal];
    for (var s = 0; s < STAGE_COUNT; s++) {
      var t = NODE_T_START + (s / (STAGE_COUNT - 1)) * (NODE_T_END - NODE_T_START);
      var pos = railCurve.getPointAt(t);
      var mat = new THREE.SpriteMaterial({
        map: glowTex, color: stageColors[s], transparent: true,
        opacity: 0.5, blending: THREE.AdditiveBlending, depthWrite: false
      });
      var sprite = new THREE.Sprite(mat);
      sprite.position.copy(pos);
      sprite.scale.set(6, 6, 1);
      sprite.userData = { baseScale: 6, activeScale: 11, baseOpacity: 0.5, activeOpacity: 1 };
      scene.add(sprite);
      stageSprites.push(sprite);
    }
  }

  function setActiveStage(idx) {
    if (idx === activeStageIndex) return;
    activeStageIndex = idx;
    stageSprites.forEach(function (sprite, i) {
      var active = i === idx;
      var s = active ? sprite.userData.activeScale : sprite.userData.baseScale;
      var o = active ? sprite.userData.activeOpacity : sprite.userData.baseOpacity;
      if (window.gsap && !reduceMotion) {
        gsap.to(sprite.scale, { x: s, y: s, duration: 0.5, ease: 'power2.out', overwrite: true });
        gsap.to(sprite.material, { opacity: o, duration: 0.5, ease: 'power2.out', overwrite: true });
      } else {
        sprite.scale.set(s, s, 1);
        sprite.material.opacity = o;
      }
    });
    window.dispatchEvent(new CustomEvent('scene3d:active-stage', { detail: { index: idx } }));
  }

  function setRailProgress(t) {
    if (!railCurve) return;
    railActive = true;
    focusMode = 'rail';
    t = Math.max(0, Math.min(1, t));
    var curveT = NODE_T_START + t * (NODE_T_END - NODE_T_START);
    var camT = Math.max(0.015, Math.min(0.985, curveT - 0.05));
    var lookT = Math.min(0.995, camT + 0.08);
    desiredPos.copy(railCurve.getPointAt(camT));
    desiredLook.copy(railCurve.getPointAt(lookT));

    var idx = Math.round(t * (STAGE_COUNT - 1));
    setActiveStage(Math.max(0, Math.min(STAGE_COUNT - 1, idx)));
  }

  function setRailInactive() {
    railActive = false;
    setActiveStage(-1);
    maybeIdle();
  }

  // ============================================================
  // LIVE THREAT CONSTELLATION — real /api/feeds/live data.
  // ============================================================
  function severityColor(score) {
    score = score || 0;
    if (score >= 80) return COLOR.danger;
    if (score >= 60) return COLOR.amber;
    if (score >= 40) return COLOR.intel;
    return COLOR.muted;
  }

  function constellationNodePosition(key, score) {
    var theta = hashUnit(key, 'theta') * Math.PI * 2;
    var phi = Math.acos(2 * hashUnit(key, 'phi') - 1);
    var radius = 46 + (100 - clamp(score, 0, 100)) * 0.3 + hashUnit(key, 'r') * 14;
    return new THREE.Vector3(
      radius * Math.sin(phi) * Math.cos(theta),
      radius * Math.cos(phi) * 0.55,
      radius * Math.sin(phi) * Math.sin(theta)
    );
  }

  function buildConstellationGroup(glowTex) {
    CONST_CAM_START = new THREE.Vector3(0, 26, -900);
    CONST_CAM_END = new THREE.Vector3(46, -14, -1120);
    CONST_LOOK_START = new THREE.Vector3(0, 4, -960);
    CONST_LOOK_END = new THREE.Vector3(10, -6, -1180);

    constellationGroup = new THREE.Group();
    constellationGroup.position.set(0, 0, CONSTELLATION_Z);
    scene.add(constellationGroup);

    constellationArcsGroup = new THREE.Group();
    constellationGroup.add(constellationArcsGroup);

    var sunMat = new THREE.SpriteMaterial({ map: glowTex, color: COLOR.signal, transparent: true, opacity: 0.9, blending: THREE.AdditiveBlending, depthWrite: false });
    constellationSun = new THREE.Sprite(sunMat);
    constellationSun.scale.set(14, 14, 1);
    constellationGroup.add(constellationSun);

    constellationNodes = new Map();
  }

  function setConstellationData(list) {
    if (!constellationGroup) return;
    list = Array.isArray(list) ? list : [];
    var seen = {};

    list.forEach(function (item) {
      var key = item.url || item.id || ('row-' + list.indexOf(item));
      seen[key] = true;
      var score = item.phish_score || item.score || 0;

      var existing = constellationNodes.get(key);
      if (existing) { existing.data = item; existing.sprite.userData.data = item; return; }

      var color = severityColor(score);
      var pos = constellationNodePosition(key, score);
      var mat = new THREE.SpriteMaterial({ map: sharedGlow, color: color, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false });
      var sprite = new THREE.Sprite(mat);
      sprite.position.copy(pos);
      sprite.scale.set(0.001, 0.001, 1);
      sprite.userData = { kind: 'live', data: item };
      constellationGroup.add(sprite);

      var mid = pos.clone().multiplyScalar(0.5).add(new THREE.Vector3(0, 12, 0));
      var arcGeo = new THREE.BufferGeometry();
      arcGeo.setAttribute('position', new THREE.BufferAttribute(quadPoints(new THREE.Vector3(0, 0, 0), mid, pos, 16), 3));
      var arcMat = new THREE.LineBasicMaterial({ color: color, transparent: true, opacity: 0 });
      var arcLine = new THREE.Line(arcGeo, arcMat);
      constellationArcsGroup.add(arcLine);

      var targetScale = 3.2 + Math.min(score, 100) / 100 * 3.4;
      var targetArcOpacity = 0.14 + (clamp(score, 0, 100) / 100) * 0.32;
      constellationNodes.set(key, { sprite: sprite, arc: arcLine, data: item });

      if (window.gsap && !reduceMotion) {
        gsap.to(sprite.scale, { x: targetScale, y: targetScale, duration: 0.9, ease: 'back.out(2)', delay: Math.random() * 0.35 });
        gsap.to(mat, { opacity: 0.92, duration: 0.7, delay: Math.random() * 0.35 });
        gsap.to(arcMat, { opacity: targetArcOpacity, duration: 1, delay: 0.15 + Math.random() * 0.35 });
      } else {
        sprite.scale.set(targetScale, targetScale, 1);
        mat.opacity = 0.92;
        arcMat.opacity = targetArcOpacity;
      }
    });

    constellationNodes.forEach(function (entry, key) {
      if (seen[key]) return;
      constellationNodes.delete(key);
      if (window.gsap && !reduceMotion) {
        gsap.to(entry.sprite.scale, { x: 0.001, y: 0.001, duration: 0.45, ease: 'power2.in', onComplete: function () { disposeSprite(entry.sprite); } });
        gsap.to(entry.sprite.material, { opacity: 0, duration: 0.35 });
        gsap.to(entry.arc.material, { opacity: 0, duration: 0.35, onComplete: function () { disposeLine(entry.arc); } });
      } else {
        disposeSprite(entry.sprite);
        disposeLine(entry.arc);
      }
    });

    constellationInteractive = [];
    constellationNodes.forEach(function (entry) { constellationInteractive.push(entry.sprite); });

    var emptyEl = document.getElementById('constellation-empty');
    if (emptyEl) emptyEl.style.display = list.length ? 'none' : 'flex';
  }

  function updateConstellation(t) {
    if (!constellationGroup) return;
    if (!reduceMotion) constellationGroup.rotation.y = t * 0.05 + constellationExtraSpin;
    if (constellationSun) constellationSun.scale.setScalar(14 + Math.sin(t * 1.4) * 1.4);
  }

  function setConstellationProgress(t) {
    if (!constellationGroup || !desiredPos) return;
    constellationActive = true;
    focusMode = 'constellation';
    t = clamp(t, 0, 1);
    desiredPos.set(lerp(CONST_CAM_START.x, CONST_CAM_END.x, t), lerp(CONST_CAM_START.y, CONST_CAM_END.y, t), lerp(CONST_CAM_START.z, CONST_CAM_END.z, t));
    desiredLook.set(lerp(CONST_LOOK_START.x, CONST_LOOK_END.x, t), lerp(CONST_LOOK_START.y, CONST_LOOK_END.y, t), lerp(CONST_LOOK_START.z, CONST_LOOK_END.z, t));
    constellationExtraSpin = t * 0.6;
  }

  function setConstellationInactive() {
    constellationActive = false;
    maybeIdle();
  }

  // ============================================================
  // ACTOR CLUSTER GRAPH — real /api/actors data + a tiny in-browser
  // force simulation (repulsion + brand-overlap springs + centering).
  // ============================================================
  function forceLayoutActors(actorList, edges, iterations) {
    var n = actorList.length;
    var pos = actorList.map(function () {
      var v = new THREE.Vector3(Math.random() - 0.5, Math.random() - 0.5, Math.random() - 0.5);
      v.normalize().multiplyScalar(28 + Math.random() * 10);
      return v;
    });
    var vel = actorList.map(function () { return new THREE.Vector3(); });
    var idIndex = {};
    actorList.forEach(function (a, i) { idIndex[a.id] = i; });

    var i, j, iter;
    for (iter = 0; iter < iterations; iter++) {
      var forces = actorList.map(function () { return new THREE.Vector3(); });
      for (i = 0; i < n; i++) {
        for (j = i + 1; j < n; j++) {
          var delta = new THREE.Vector3().subVectors(pos[i], pos[j]);
          var distSq = Math.max(delta.lengthSq(), 4);
          delta.normalize().multiplyScalar(900 / distSq);
          forces[i].add(delta);
          forces[j].sub(delta);
        }
      }
      edges.forEach(function (e) {
        var a = idIndex[e.a], b = idIndex[e.b];
        if (a === undefined || b === undefined) return;
        var delta = new THREE.Vector3().subVectors(pos[b], pos[a]);
        var dist = Math.max(delta.length(), 0.01);
        var f = (dist - 34) * 0.02 * e.weight;
        delta.normalize().multiplyScalar(f);
        forces[a].add(delta);
        forces[b].sub(delta);
      });
      for (i = 0; i < n; i++) forces[i].add(pos[i].clone().multiplyScalar(-0.01));
      for (i = 0; i < n; i++) {
        vel[i].add(forces[i]).multiplyScalar(0.82);
        pos[i].add(vel[i]);
      }
    }
    return pos;
  }

  function recencyColor(iso) {
    if (!iso) return 0x5c6a6d;
    var days = clamp((Date.now() - new Date(iso).getTime()) / 86400000 / 30, 0, 1);
    return new THREE.Color(COLOR.signal).lerp(new THREE.Color(0x3a4547), days).getHex();
  }

  function buildActorGraphGroup() {
    ACTORGRAPH_CAM = { pos: new THREE.Vector3(0, 14, 92), look: new THREE.Vector3(0, 0, 0) };
    actorGraphGroup = new THREE.Group();
    scene.add(actorGraphGroup);
  }

  function setActorGraphData(actorList) {
    if (!actorGraphGroup) return;
    actorGraphInteractive.forEach(function (s) { disposeSprite(s); });
    actorGraphInteractive = [];
    if (actorGraphEdges) { disposeLine(actorGraphEdges); actorGraphEdges = null; }

    actorList = Array.isArray(actorList) ? actorList : [];
    var emptyEl = document.getElementById('actorgraph-empty');
    if (emptyEl) emptyEl.style.display = actorList.length ? 'none' : 'flex';
    actorGraphBuilt = true;
    if (!actorList.length) return;

    var edges = [], i, j;
    for (i = 0; i < actorList.length; i++) {
      for (j = i + 1; j < actorList.length; j++) {
        var bi = actorList[i].brands || [], bj = actorList[j].brands || [];
        var shared = bi.filter(function (b) { return bj.indexOf(b) !== -1; });
        if (shared.length) edges.push({ a: actorList[i].id, b: actorList[j].id, weight: shared.length });
      }
    }

    var positions3 = forceLayoutActors(actorList, edges, actorList.length > 1 ? 220 : 1);

    actorList.forEach(function (actor, idx) {
      var color = recencyColor(actor.last_seen);
      var scale = 3 + Math.sqrt(Math.max(actor.kit_count || 1, 1)) * 1.7;
      var mat = new THREE.SpriteMaterial({ map: sharedGlow, color: color, transparent: true, opacity: 0, blending: THREE.AdditiveBlending, depthWrite: false });
      var sprite = new THREE.Sprite(mat);
      sprite.position.copy(positions3[idx]);
      sprite.scale.set(0.001, 0.001, 1);
      sprite.userData = { kind: 'actor', data: actor };
      actorGraphGroup.add(sprite);
      actorGraphInteractive.push(sprite);

      if (window.gsap && !reduceMotion) {
        gsap.to(sprite.scale, { x: scale, y: scale, duration: 0.8, ease: 'back.out(2)', delay: idx * 0.03 });
        gsap.to(mat, { opacity: 0.92, duration: 0.6, delay: idx * 0.03 });
      } else {
        sprite.scale.set(scale, scale, 1);
        mat.opacity = 0.92;
      }
    });

    if (edges.length) {
      var linePositions = new Float32Array(edges.length * 6);
      edges.forEach(function (e, idx) {
        var pa = positions3[actorList.findIndex(function (a) { return a.id === e.a; })];
        var pb = positions3[actorList.findIndex(function (a) { return a.id === e.b; })];
        var o = idx * 6;
        linePositions[o] = pa.x; linePositions[o + 1] = pa.y; linePositions[o + 2] = pa.z;
        linePositions[o + 3] = pb.x; linePositions[o + 4] = pb.y; linePositions[o + 5] = pb.z;
      });
      var lineGeo = new THREE.BufferGeometry();
      lineGeo.setAttribute('position', new THREE.BufferAttribute(linePositions, 3));
      actorGraphEdges = new THREE.LineSegments(lineGeo, new THREE.LineBasicMaterial({ color: COLOR.intel, transparent: true, opacity: 0.2 }));
      actorGraphGroup.add(actorGraphEdges);
    }
  }

  function updateActorGraph(t) {
    if (!actorGraphGroup || reduceMotion) return;
    actorGraphGroup.rotation.y = t * 0.045;
  }

  function setActorGraphActive(active) {
    if (!desiredPos) return;
    actorGraphActive = !!active;
    if (actorGraphActive) {
      focusMode = 'actorgraph';
      desiredPos.copy(ACTORGRAPH_CAM.pos);
      desiredLook.copy(ACTORGRAPH_CAM.look);
    } else {
      maybeIdle();
    }
  }

  // ============================================================
  // LIVE INDICATOR DATA STREAM — real /api/ioc data, drifting helix.
  // ============================================================
  function buildStreamGroup() {
    STREAM_KIND_COLOR = {
      telegram_token: COLOR.intel, telegram_chat: COLOR.intel,
      discord_webhook: COLOR.violet, email: COLOR.amber, smtp: COLOR.danger, url: COLOR.signal
    };
    STREAM_CAM = { pos: new THREE.Vector3(0, 10, 88), look: new THREE.Vector3(0, 0, 0) };
    streamGroup = new THREE.Group();
    scene.add(streamGroup);
  }

  function setDataStreamData(list) {
    if (!streamGroup) return;
    streamTiles.forEach(function (tile) {
      if (tile.sprite.material.map) tile.sprite.material.map.dispose();
      disposeSprite(tile.sprite);
    });
    streamTiles = [];
    streamInteractive = [];
    streamBuilt = true;

    list = (Array.isArray(list) ? list : []).slice(0, 36);
    var emptyEl = document.getElementById('datastream-empty');
    if (emptyEl) emptyEl.style.display = list.length ? 'none' : 'flex';

    var golden = 2.399963;
    list.forEach(function (item, i) {
      var kind = item.kind || item.type || 'url';
      var valueText = item.value || item.redacted_display || '—';
      var subText = (item.brand || '') + (item.actor_label ? '  ·  ' + item.actor_label : '');
      var tex = makeLabelTexture(kind, valueText, subText || 'unattributed');
      var mat = new THREE.SpriteMaterial({ map: tex, transparent: true, opacity: 0, depthWrite: false });
      var sprite = new THREE.Sprite(mat);
      sprite.scale.set(15.5, 7.4, 1);

      var angle = i * golden;
      var radius = 34 + (i % 4) * 9;
      var baseY = (i - list.length / 2) * 5.6;
      sprite.position.set(Math.cos(angle) * radius, baseY, Math.sin(angle) * radius);
      sprite.userData = { kind: 'ioc', data: item };
      streamGroup.add(sprite);

      var tile = { sprite: sprite, baseY: baseY, angle: angle, speed: 0.15 + Math.random() * 0.1 };
      streamTiles.push(tile);
      streamInteractive.push(sprite);

      if (window.gsap && !reduceMotion) {
        gsap.to(mat, { opacity: 0.95, duration: 0.6, delay: i * 0.02 });
      } else {
        mat.opacity = 0.95;
      }
    });
  }

  function updateDataStream(t) {
    if (!streamGroup || reduceMotion) return;
    streamGroup.rotation.y = t * 0.06;
    streamTiles.forEach(function (tile) {
      tile.sprite.position.y = tile.baseY + Math.sin(t * tile.speed + tile.angle) * 6;
    });
  }

  function setDataStreamActive(active) {
    if (!desiredPos) return;
    streamActive = !!active;
    if (streamActive) {
      focusMode = 'datastream';
      desiredPos.copy(STREAM_CAM.pos);
      desiredLook.copy(STREAM_CAM.look);
    } else {
      maybeIdle();
    }
  }

  // ============================================================
  // TAKEDOWN FLOW — real /api/feeds/takedowns data. A dispatch hub with
  // target nodes derived from the actual distinct target_type values seen
  // in the data; every real dispatch fires a packet that flies hub→target
  // and bursts on arrival. History accumulates as target-node brightness
  // (hit count) rather than replaying every past flight, so a page with
  // months of takedowns doesn't turn into packet spam — only genuinely
  // new dispatches (and a handful of the most recent on first load) fly.
  // ============================================================
  function targetColorFor(type) {
    var t = String(type || '').toLowerCase();
    for (var i = 0; i < TARGET_TYPE_COLOR_RULES.length; i++) {
      if (TARGET_TYPE_COLOR_RULES[i][0].test(t)) return TARGET_TYPE_COLOR_RULES[i][1];
    }
    return COLOR.signal;
  }

  function makeTargetLabelTexture(text, colorHex) {
    var w = 220, h = 64;
    var c = document.createElement('canvas');
    c.width = w; c.height = h;
    var ctx = c.getContext('2d');
    var colorStr = '#' + new THREE.Color(colorHex).getHexString();
    ctx.fillStyle = 'rgba(8,10,11,0.78)';
    ctx.fillRect(0, 0, w, h);
    ctx.strokeStyle = colorStr;
    ctx.lineWidth = 2.5;
    ctx.strokeRect(1.5, 1.5, w - 3, h - 3);
    ctx.fillStyle = colorStr;
    ctx.font = '600 22px "IBM Plex Mono", monospace';
    ctx.textAlign = 'center';
    ctx.fillText(String(text || '').toUpperCase(), w / 2, h / 2 + 8);
    var tex = new THREE.CanvasTexture(c);
    tex.needsUpdate = true;
    return tex;
  }

  function buildTakedownGroup(glowTex) {
    TAKEDOWN_CAM_START = new THREE.Vector3(-30, 20, -1120);
    TAKEDOWN_CAM_END = new THREE.Vector3(10, -18, -1420);
    TAKEDOWN_LOOK_START = new THREE.Vector3(0, 0, -1230);
    TAKEDOWN_LOOK_END = new THREE.Vector3(-6, -4, -1360);

    takedownGroup = new THREE.Group();
    takedownGroup.position.set(0, 0, TAKEDOWN_Z);
    scene.add(takedownGroup);

    var hubMat = new THREE.SpriteMaterial({ map: glowTex, color: COLOR.amber, transparent: true, opacity: 0.92, blending: THREE.AdditiveBlending, depthWrite: false });
    takedownHub = new THREE.Sprite(hubMat);
    takedownHub.scale.set(13, 13, 1);
    takedownGroup.add(takedownHub);
  }

  function rebuildTakedownTargets(types) {
    Object.keys(takedownTargets).forEach(function (key) {
      var entry = takedownTargets[key];
      var idx = takedownInteractive.indexOf(entry.node);
      if (idx !== -1) takedownInteractive.splice(idx, 1);
      disposeSprite(entry.node);
      if (entry.label.material.map) entry.label.material.map.dispose();
      disposeSprite(entry.label);
    });
    takedownTargets = {};

    var radius = 46;
    types.forEach(function (type, i) {
      var angle = (i / types.length) * Math.PI * 2;
      var pos = new THREE.Vector3(Math.cos(angle) * radius, Math.sin(i * 1.7) * 10, Math.sin(angle) * radius);
      var color = targetColorFor(type);

      var nodeMat = new THREE.SpriteMaterial({ map: sharedGlow, color: color, transparent: true, opacity: 0.7, blending: THREE.AdditiveBlending, depthWrite: false });
      var node = new THREE.Sprite(nodeMat);
      node.position.copy(pos);
      node.scale.set(6, 6, 1);
      node.userData = { kind: 'takedown-target', data: { target_type: type, hitCount: 0 } };
      takedownGroup.add(node);
      takedownInteractive.push(node);

      var label = new THREE.Sprite(new THREE.SpriteMaterial({ map: makeTargetLabelTexture(type, color), transparent: true, opacity: 0.95, depthWrite: false }));
      label.scale.set(15, 4.4, 1);
      label.position.copy(pos).add(new THREE.Vector3(0, 9, 0));
      takedownGroup.add(label);

      takedownTargets[type] = { node: node, label: label, pos: pos, hitCount: 0, color: color };
    });
  }

  function updateTargetIntensity(entry) {
    entry.node.userData.data.hitCount = entry.hitCount;
    var s = 6 + Math.sqrt(entry.hitCount) * 1.6;
    var o = Math.min(0.95, 0.55 + entry.hitCount * 0.02);
    if (window.gsap && !reduceMotion) {
      gsap.to(entry.node.scale, { x: s, y: s, duration: 0.5, overwrite: true });
      gsap.to(entry.node.material, { opacity: o, duration: 0.5, overwrite: true });
    } else {
      entry.node.scale.set(s, s, 1);
      entry.node.material.opacity = o;
    }
  }

  function flightPoint(pathPts, t) {
    var segs = pathPts.length / 3 - 1;
    var f = clamp(t, 0, 1) * segs;
    var i = Math.min(segs - 1, Math.floor(f));
    var lt = f - i;
    return new THREE.Vector3(
      lerp(pathPts[i * 3], pathPts[(i + 1) * 3], lt),
      lerp(pathPts[i * 3 + 1], pathPts[(i + 1) * 3 + 1], lt),
      lerp(pathPts[i * 3 + 2], pathPts[(i + 1) * 3 + 2], lt)
    );
  }

  function spawnImpact(atV, color) {
    if (!takedownGroup || reduceMotion || !window.gsap) return;
    var mat = new THREE.SpriteMaterial({ map: sharedGlow, color: color, transparent: true, opacity: 0.85, blending: THREE.AdditiveBlending, depthWrite: false });
    var sprite = new THREE.Sprite(mat);
    sprite.position.copy(atV);
    sprite.scale.set(3, 3, 1);
    takedownGroup.add(sprite);
    gsap.to(sprite.scale, { x: 17, y: 17, duration: 0.6, ease: 'power2.out' });
    gsap.to(mat, { opacity: 0, duration: 0.6, ease: 'power2.out', onComplete: function () { disposeSprite(sprite); } });
  }

  function spawnPacket(fromV, toV, color) {
    if (!takedownGroup) return;
    if (!window.gsap || reduceMotion) { spawnImpact(toV, color); return; }

    var mid = fromV.clone().add(toV).multiplyScalar(0.5).add(new THREE.Vector3(0, 14, 0));
    var pathPts = quadPoints(fromV, mid, toV, 24);

    var mat = new THREE.SpriteMaterial({ map: sharedGlow, color: color, transparent: true, opacity: 0.95, blending: THREE.AdditiveBlending, depthWrite: false });
    var sprite = new THREE.Sprite(mat);
    sprite.scale.set(2.6, 2.6, 1);
    sprite.position.copy(fromV);
    takedownGroup.add(sprite);
    // Packets are transient (~1s flight) and not added to the interactive
    // list — only the persistent target nodes are click/hover targets.

    var proxy = { t: 0 };
    gsap.to(proxy, {
      t: 1, duration: 1.05 + Math.random() * 0.3, ease: 'power1.inOut',
      onUpdate: function () { sprite.position.copy(flightPoint(pathPts, proxy.t)); },
      onComplete: function () {
        disposeSprite(sprite);
        spawnImpact(toV, color);
      }
    });
  }

  function setTakedownFlowData(list) {
    if (!takedownGroup) return;
    list = Array.isArray(list) ? list : [];

    var emptyEl = document.getElementById('takedownflow-empty');
    if (emptyEl) emptyEl.style.display = list.length ? 'none' : 'flex';
    takedownBuilt = true;
    if (!list.length) return;

    var counts = {};
    list.forEach(function (t) {
      var type = (t.target_type || 'host').toLowerCase();
      counts[type] = (counts[type] || 0) + 1;
    });
    var types = Object.keys(counts).sort(function (a, b) { return counts[b] - counts[a]; }).slice(0, 6);
    var typeSet = {};
    types.forEach(function (tt) { typeSet[tt] = true; });

    var existingKeys = Object.keys(takedownTargets);
    var sameSet = existingKeys.length === types.length && existingKeys.every(function (k) { return typeSet[k]; });
    if (!sameSet) rebuildTakedownTargets(types);

    var isFirstLoad = seenTakedownIds === null;
    if (isFirstLoad) seenTakedownIds = {};

    var toFly = [];
    list.forEach(function (t, idx) {
      var id = t.id !== undefined && t.id !== null ? t.id : (t.contact + '|' + t.sent_at + '|' + idx);
      var type = (t.target_type || 'host').toLowerCase();
      var entry = takedownTargets[type];
      if (!entry) return;
      if (seenTakedownIds[id]) return;
      seenTakedownIds[id] = true;
      entry.hitCount++;
      if (!isFirstLoad || idx < 5) toFly.push(entry);
    });

    toFly.forEach(function (entry, i) {
      setTimeout(function () {
        if (!takedownGroup) return;
        spawnPacket(new THREE.Vector3(0, 0, 0), entry.pos, entry.color);
      }, i * 170);
    });

    Object.keys(takedownTargets).forEach(function (type) { updateTargetIntensity(takedownTargets[type]); });
  }

  function updateTakedownFlow(t) {
    if (!takedownGroup) return;
    if (!reduceMotion) takedownGroup.rotation.y = t * 0.035;
    if (takedownHub) takedownHub.scale.setScalar(13 + Math.sin(t * 1.2) * 1.6);
  }

  function setTakedownProgress(t) {
    if (!takedownGroup || !desiredPos) return;
    takedownActive = true;
    focusMode = 'takedownflow';
    t = clamp(t, 0, 1);
    desiredPos.set(lerp(TAKEDOWN_CAM_START.x, TAKEDOWN_CAM_END.x, t), lerp(TAKEDOWN_CAM_START.y, TAKEDOWN_CAM_END.y, t), lerp(TAKEDOWN_CAM_START.z, TAKEDOWN_CAM_END.z, t));
    desiredLook.set(lerp(TAKEDOWN_LOOK_START.x, TAKEDOWN_LOOK_END.x, t), lerp(TAKEDOWN_LOOK_START.y, TAKEDOWN_LOOK_END.y, t), lerp(TAKEDOWN_LOOK_START.z, TAKEDOWN_LOOK_END.z, t));
  }

  function setTakedownInactive() {
    takedownActive = false;
    maybeIdle();
  }

  // ============================================================
  // RAYCAST HOVER / CLICK + DRAG-TO-ORBIT
  // (attached only to pages that render a #*-stage element — the
  // hero/rail-only pages never register listeners, so idle/rail
  // behavior is untouched.)
  // ============================================================
  function currentInteractive() {
    if (focusMode === 'constellation') return constellationInteractive;
    if (focusMode === 'actorgraph') return actorGraphInteractive;
    if (focusMode === 'datastream') return streamInteractive;
    if (focusMode === 'takedownflow') return takedownInteractive;
    return EMPTY_ARR;
  }

  function ndcFromClient(clientX, clientY) {
    ndc.x = (clientX / window.innerWidth) * 2 - 1;
    ndc.y = -(clientY / window.innerHeight) * 2 + 1;
    return ndc;
  }

  function pickAt(clientX, clientY) {
    var list = currentInteractive();
    if (!list.length) return null;
    raycaster.setFromCamera(ndcFromClient(clientX, clientY), camera);
    var hits = raycaster.intersectObjects(list, false);
    return hits.length ? hits[0].object : null;
  }

  function setHover(obj, clientX, clientY) {
    if (obj === hoveredObject) {
      if (obj) window.dispatchEvent(new CustomEvent('scene3d:node-pos', { detail: { x: clientX, y: clientY } }));
      return;
    }
    if (hoveredObject && hoveredObject.userData.__baseScale) {
      hoveredObject.scale.copy(hoveredObject.userData.__baseScale);
    }
    hoveredObject = obj;
    if (obj) {
      if (!obj.userData.__baseScale) obj.userData.__baseScale = obj.scale.clone();
      obj.scale.copy(obj.userData.__baseScale).multiplyScalar(1.35);
      document.body.style.cursor = 'pointer';
      window.dispatchEvent(new CustomEvent('scene3d:node-hover', { detail: { kind: obj.userData.kind, data: obj.userData.data, x: clientX, y: clientY } }));
    } else {
      document.body.style.cursor = '';
      window.dispatchEvent(new CustomEvent('scene3d:node-hover-end'));
    }
  }

  function onHoverMove(e) {
    if (dragging) return;
    setHover(pickAt(e.clientX, e.clientY), e.clientX, e.clientY);
  }

  function onWindowDragMove(e) {
    var dx = e.clientX - dragLastX, dy = e.clientY - dragLastY;
    if (Math.abs(dx) + Math.abs(dy) > 3) dragMoved = true;
    dragYaw -= dx * 0.006;
    dragPitch = clamp(dragPitch - dy * 0.006, -0.65, 0.65);
    dragVelYaw = -dx * 0.006;
    dragVelPitch = -dy * 0.006;
    dragLastX = e.clientX; dragLastY = e.clientY;
  }

  function wireStageInteractivity(el) {
    if (!el) return;
    el.style.cursor = 'grab';
    el.addEventListener('pointermove', onHoverMove);
    el.addEventListener('pointerleave', function () { if (!dragging) setHover(null); });
    el.addEventListener('pointerdown', function (e) {
      dragging = true; dragMoved = false;
      dragLastX = e.clientX; dragLastY = e.clientY;
      dragVelYaw = 0; dragVelPitch = 0;
      el.style.cursor = 'grabbing';

      function onUp(e2) {
        dragging = false;
        el.style.cursor = 'grab';
        window.removeEventListener('pointermove', onWindowDragMove);
        window.removeEventListener('pointerup', onUp);
        if (!dragMoved) {
          var obj = pickAt(e2.clientX, e2.clientY);
          if (obj) window.dispatchEvent(new CustomEvent('scene3d:node-click', { detail: { kind: obj.userData.kind, data: obj.userData.data } }));
        }
      }
      window.addEventListener('pointermove', onWindowDragMove);
      window.addEventListener('pointerup', onUp);
    });
  }

  function applyOrbitOffset(pos, look) {
    if (!dragYaw && !dragPitch) return pos;
    _dir.subVectors(pos, look);
    _sph.setFromVector3(_dir);
    _sph.theta += dragYaw;
    _sph.phi = clamp(_sph.phi + dragPitch, 0.2, Math.PI - 0.2);
    _dir.setFromSpherical(_sph);
    _orbitPos.addVectors(look, _dir);
    return _orbitPos;
  }

  // ============================================================
  // IDLE CAMERA DRIFT (unchanged from original)
  // ============================================================
  function idleUpdate(t) {
    desiredPos.set(Math.sin(t * 0.05) * 46, Math.cos(t * 0.04) * 16 + 6, 130 + Math.sin(t * 0.025) * 26);
    desiredLook.set(Math.sin(t * 0.045) * 12, 2, desiredPos.z - 160);
  }

  function resize() {
    var w = window.innerWidth, h = window.innerHeight;
    renderer.setSize(w, h);
    camera.aspect = w / h;
    camera.updateProjectionMatrix();
  }

  // ============================================================
  // MAIN LOOP
  // ============================================================
  function animate() {
    requestAnimationFrame(animate);
    if (!running) return;
    var t = clock.getElapsedTime();

    if (focusMode === 'idle') idleUpdate(t);

    updateField();
    updateCore(t);
    if (constellationGroup) updateConstellation(t);
    if (actorGraphBuilt) updateActorGraph(t);
    if (streamBuilt) updateDataStream(t);
    if (takedownBuilt) updateTakedownFlow(t);

    frameCount++;
    if (!reduceMotion && frameCount % 50 === 0) rebuildLinks();
    if (!reduceMotion) fieldGroup.rotation.y += 0.0009;

    if (!dragging && (Math.abs(dragVelYaw) > 0.00003 || Math.abs(dragVelPitch) > 0.00003)) {
      dragYaw += dragVelYaw;
      dragPitch = clamp(dragPitch + dragVelPitch, -0.65, 0.65);
      dragVelYaw *= 0.92;
      dragVelPitch *= 0.92;
    }

    var fieldTarget = focusMode === 'idle' ? 0.8 : 0.3;
    fieldMat.opacity += (fieldTarget - fieldMat.opacity) * 0.04;

    var parX = mouseNX * 8, parY = -mouseNY * 5;
    _tmpCamTarget.set(desiredPos.x + parX, desiredPos.y + parY, desiredPos.z);
    var orbited = applyOrbitOffset(_tmpCamTarget, desiredLook);
    camera.position.lerp(orbited, reduceMotion ? 1 : 0.045);
    _tmpLookTarget.set(desiredLook.x + parX * 0.4, desiredLook.y + parY * 0.4, desiredLook.z);
    camera.lookAt(_tmpLookTarget);

    renderer.render(scene, camera);
  }

  function init(opts) {
    if (initialized) return;
    initialized = true;
    opts = opts || {};

    renderer = new THREE.WebGLRenderer({ canvas: canvas, antialias: true, powerPreference: 'high-performance' });
    renderer.setClearColor(COLOR.voidColor, 1);
    renderer.setPixelRatio(Math.min(window.devicePixelRatio || 1, 1.75));

    scene = new THREE.Scene();
    scene.fog = new THREE.FogExp2(COLOR.voidColor, 0.006);

    camera = new THREE.PerspectiveCamera(55, window.innerWidth / window.innerHeight, 0.1, 1000);
    camera.position.set(0, 6, 130);

    desiredPos = new THREE.Vector3(0, 6, 130);
    desiredLook = new THREE.Vector3(0, 0, 0);
    _tmpCamTarget = new THREE.Vector3();
    _tmpLookTarget = new THREE.Vector3();
    raycaster = new THREE.Raycaster();
    ndc = new THREE.Vector2();
    _sph = new THREE.Spherical();
    _dir = new THREE.Vector3();
    _orbitPos = new THREE.Vector3();

    var glowTex = makeGlowTexture();
    sharedGlow = glowTex;
    buildField(glowTex);
    if (opts.withCore !== false) buildCore(glowTex);
    if (opts.withRail) buildRail(glowTex);
    if (opts.withConstellation) buildConstellationGroup(glowTex);
    if (opts.withActorGraph) buildActorGraphGroup();
    if (opts.withDataStream) buildStreamGroup();
    if (opts.withTakedownFlow) buildTakedownGroup(glowTex);

    wireStageInteractivity(document.getElementById('constellation-stage'));
    wireStageInteractivity(document.getElementById('actorgraph-stage'));
    wireStageInteractivity(document.getElementById('datastream-stage'));
    wireStageInteractivity(document.getElementById('takedownflow-stage'));

    clock = new THREE.Clock();
    resize();
    window.addEventListener('resize', resize, { passive: true });

    window.addEventListener('mousemove', function (e) {
      mouseNX = (e.clientX / window.innerWidth) * 2 - 1;
      mouseNY = (e.clientY / window.innerHeight) * 2 - 1;
    }, { passive: true });

    document.addEventListener('visibilitychange', function () {
      running = !document.hidden;
    });

    rebuildLinks();
    animate();

    window.Scene3D.ready = true;
    window.Scene3D.isSupported = true;
    window.Scene3D.hasRail = !!opts.withRail;
  }

  window.Scene3D = {
    isSupported: true,
    ready: false,
    hasRail: false,
    init: init,
    setRailProgress: setRailProgress,
    setRailInactive: setRailInactive,
    setActiveStage: setActiveStage,
    setConstellationData: setConstellationData,
    setConstellationProgress: setConstellationProgress,
    setConstellationInactive: setConstellationInactive,
    setActorGraphData: setActorGraphData,
    setActorGraphActive: setActorGraphActive,
    setDataStreamData: setDataStreamData,
    setDataStreamActive: setDataStreamActive,
    setTakedownFlowData: setTakedownFlowData,
    setTakedownProgress: setTakedownProgress,
    setTakedownInactive: setTakedownInactive
  };
})();
