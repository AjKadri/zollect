/* Original illustrations for Zollect: avatars, zote artwork, hero globe. */
(function () {
  const AVATARS = {
    kemi: `
<svg viewBox="0 0 120 140" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Illustration of Kemi">
  <defs>
    <linearGradient id="kbg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#B9C0FF"/><stop offset="1" stop-color="#8C96FF"/></linearGradient>
    <linearGradient id="kskin" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#8A5434"/><stop offset="1" stop-color="#6E3F25"/></linearGradient>
  </defs>
  <rect width="120" height="140" fill="url(#kbg)"/>
  <!-- bun of braids -->
  <circle cx="60" cy="24" r="17" fill="#1C1311"/>
  <path d="M47 18c8 6 18 6 26 0M46 26c9 6 19 6 28 0" stroke="#3A2722" stroke-width="2" fill="none" stroke-linecap="round"/>
  <!-- shoulders / top -->
  <path d="M18 140c2-26 18-38 42-38s40 12 42 38z" fill="#A9F2CB"/>
  <path d="M48 104c4 8 20 8 24 0" stroke="#7ED9AB" stroke-width="3" fill="none" stroke-linecap="round"/>
  <!-- neck -->
  <path d="M51 86h18v18c-4 4-14 4-18 0z" fill="#6E3F25"/>
  <!-- hair base -->
  <path d="M33 60c0-22 12-34 27-34s27 12 27 34c0 6-2 12-4 16l-4-20c-6-6-30-6-38 0l-4 20c-2-4-4-10-4-16z" fill="#1C1311"/>
  <!-- face -->
  <ellipse cx="60" cy="64" rx="22" ry="25" fill="url(#kskin)"/>
  <!-- hairline -->
  <path d="M38 56c6-14 38-14 44 0c-8-6-36-6-44 0z" fill="#1C1311"/>
  <!-- headwrap band -->
  <path d="M38 48c10-8 34-8 44 0l-2 5c-10-7-30-7-40 0z" fill="#4B55E8"/>
  <!-- ears + earrings -->
  <ellipse cx="38" cy="66" rx="4" ry="6" fill="#6E3F25"/><ellipse cx="82" cy="66" rx="4" ry="6" fill="#6E3F25"/>
  <circle cx="38" cy="77" r="4.5" fill="none" stroke="#F2C766" stroke-width="2"/>
  <circle cx="82" cy="77" r="4.5" fill="none" stroke="#F2C766" stroke-width="2"/>
  <!-- brows, eyes -->
  <path d="M47 56c3-2 7-2 10 0M63 56c3-2 7-2 10 0" stroke="#1C1311" stroke-width="2" fill="none" stroke-linecap="round"/>
  <ellipse cx="52" cy="63" rx="2.6" ry="3" fill="#1C1311"/><ellipse cx="68" cy="63" rx="2.6" ry="3" fill="#1C1311"/>
  <circle cx="53" cy="62" r=".8" fill="#fff"/><circle cx="69" cy="62" r=".8" fill="#fff"/>
  <!-- nose, cheeks, smile -->
  <path d="M59 66c-1 4-2 6 1 7" stroke="#55301C" stroke-width="1.6" fill="none" stroke-linecap="round"/>
  <ellipse cx="47" cy="72" rx="4" ry="2.4" fill="#C2665A" opacity=".35"/><ellipse cx="73" cy="72" rx="4" ry="2.4" fill="#C2665A" opacity=".35"/>
  <path d="M52 77c4 4 12 4 16 0" stroke="#3B1D12" stroke-width="2.2" fill="#fff" stroke-linecap="round"/>
</svg>`,
    tobi: `
<svg viewBox="0 0 120 140" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Illustration of Tobi">
  <defs>
    <linearGradient id="tbg" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#C6F7DD"/><stop offset="1" stop-color="#8FE3B8"/></linearGradient>
    <linearGradient id="tskin" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#76472A"/><stop offset="1" stop-color="#5B341E"/></linearGradient>
  </defs>
  <rect width="120" height="140" fill="url(#tbg)"/>
  <!-- shirt -->
  <path d="M14 140c2-28 20-40 46-40s44 12 46 40z" fill="#3940C9"/>
  <path d="M46 102l14 14 14-14" stroke="#EEF0FF" stroke-width="3" fill="none" stroke-linejoin="round"/>
  <!-- neck -->
  <path d="M50 86h20v18c-5 5-15 5-20 0z" fill="#5B341E"/>
  <!-- ears -->
  <ellipse cx="36" cy="64" rx="5" ry="7" fill="#5B341E"/><ellipse cx="84" cy="64" rx="5" ry="7" fill="#5B341E"/>
  <!-- face -->
  <path d="M37 58c0-18 10-28 23-28s23 10 23 28v8c0 16-10 26-23 26S37 82 37 66z" fill="url(#tskin)"/>
  <!-- hair: low fade with textured top -->
  <path d="M36 56c0-20 11-30 24-30s24 10 24 30c-3-8-9-12-24-12s-21 4-24 12z" fill="#16100E"/>
  <path d="M42 40c4-4 8-5 12-5M58 33c4 0 8 1 11 3M66 38c4 1 7 3 9 6" stroke="#2C211D" stroke-width="2" stroke-linecap="round"/>
  <!-- beard shadow -->
  <path d="M42 74c4 14 32 14 36 0c-2 12-10 18-18 18s-16-6-18-18z" fill="#2A1A12" opacity=".55"/>
  <!-- glasses -->
  <circle cx="51" cy="63" r="7.5" fill="rgba(255,255,255,.18)" stroke="#16100E" stroke-width="2"/>
  <circle cx="69" cy="63" r="7.5" fill="rgba(255,255,255,.18)" stroke="#16100E" stroke-width="2"/>
  <path d="M58.5 63h3M43.5 61l-6-2M76.5 61l6-2" stroke="#16100E" stroke-width="2" stroke-linecap="round"/>
  <!-- eyes, brows -->
  <circle cx="51" cy="64" r="2.4" fill="#16100E"/><circle cx="69" cy="64" r="2.4" fill="#16100E"/>
  <path d="M45 53c3-2 8-2 11 0M64 53c3-2 8-2 11 0" stroke="#16100E" stroke-width="2.2" fill="none" stroke-linecap="round"/>
  <!-- nose, smile -->
  <path d="M59 68c-1 3-2 5 1 6" stroke="#3E2214" stroke-width="1.6" fill="none" stroke-linecap="round"/>
  <path d="M53 79c4 3 10 3 14 0" stroke="#EEF0FF" stroke-width="2.4" fill="none" stroke-linecap="round"/>
</svg>`,
  };

  function mountAvatars(root = document) {
    root.querySelectorAll("[data-avatar]").forEach((el) => {
      const svg = AVATARS[el.dataset.avatar];
      if (svg && !el.firstElementChild) el.innerHTML = svg;
    });
  }

  /* Seeded generative art: "Lagos Lights" — a night skyline over the lagoon. */
  function rng(seed) {
    let s = seed >>> 0;
    return () => ((s = (s * 1664525 + 1013904223) >>> 0) / 4294967296);
  }
  const PALETTES = [
    ["#A9F2CB", "#F2C766", "#9AA3FF"],
    ["#F2C766", "#FF9E7A", "#A9F2CB"],
    ["#9AA3FF", "#A9F2CB", "#FFFFFF"],
  ];
  function zoteArt(item) {
    const r = rng(item * 7919 + 17);
    const pal = PALETTES[(item - 1) % PALETTES.length];
    const W = 400, H = 300, horizon = 196;
    let out = `<svg viewBox="0 0 ${W} ${H}" preserveAspectRatio="xMidYMid slice" xmlns="http://www.w3.org/2000/svg" role="img" aria-label="Lagos Lights #${item} artwork">`;
    out += `<defs><linearGradient id="sky${item}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#0A0F2A"/><stop offset="1" stop-color="#2A2F8F"/></linearGradient>
      <linearGradient id="sea${item}" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#151C55"/><stop offset="1" stop-color="#070A1F"/></linearGradient></defs>`;
    out += `<rect width="${W}" height="${H}" fill="url(#sky${item})"/>`;
    for (let i = 0; i < 70; i++) {
      out += `<circle cx="${(r() * W).toFixed(1)}" cy="${(r() * horizon * 0.7).toFixed(1)}" r="${(r() * 1.1 + .2).toFixed(2)}" fill="#fff" opacity="${(r() * .6 + .15).toFixed(2)}"/>`;
    }
    out += `<circle cx="${(60 + r() * 280).toFixed(0)}" cy="${(40 + r() * 40).toFixed(0)}" r="16" fill="${pal[0]}" opacity=".9"/>`;
    let x = 0; const lights = [];
    while (x < W) {
      const w = 14 + r() * 34, h = 24 + r() * 120 * (0.4 + Math.sin((x / W) * Math.PI) * 0.8);
      out += `<rect x="${x.toFixed(1)}" y="${(horizon - h).toFixed(1)}" width="${w.toFixed(1)}" height="${h.toFixed(1)}" fill="#0C1238"/>`;
      for (let wy = horizon - h + 6; wy < horizon - 6; wy += 8) for (let wx = x + 4; wx < x + w - 4; wx += 7) if (r() < 0.38) lights.push([wx, wy]);
      x += w + r() * 3;
    }
    lights.forEach(([lx, ly]) => {
      const c = pal[Math.floor(r() * pal.length)];
      out += `<rect x="${lx.toFixed(1)}" y="${ly.toFixed(1)}" width="2.6" height="2.6" fill="${c}" opacity="${(r() * .5 + .5).toFixed(2)}"/>`;
    });
    out += `<rect y="${horizon}" width="${W}" height="${H - horizon}" fill="url(#sea${item})"/>`;
    lights.forEach(([lx, ly]) => {
      if (r() < 0.35) {
        const d = horizon - ly; const c = pal[Math.floor(r() * pal.length)];
        out += `<rect x="${(lx + (r() - .5) * 3).toFixed(1)}" y="${(horizon + d * .55 + 4).toFixed(1)}" width="${(2 + r() * 6).toFixed(1)}" height="1.2" fill="${c}" opacity="${(r() * .35 + .1).toFixed(2)}"/>`;
      }
    });
    return out + "</svg>";
  }

  /* Hero globe: a slowly turning sphere of points. */
  function globe(canvas) {
    const ctx = canvas.getContext("2d");
    const reduce = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
    const N = 4200, pts = [];
    const golden = Math.PI * (3 - Math.sqrt(5));
    for (let i = 0; i < N; i++) {
      const y = 1 - (i / (N - 1)) * 2, rad = Math.sqrt(1 - y * y), th = golden * i;
      pts.push([Math.cos(th) * rad, y, Math.sin(th) * rad, Math.random()]);
    }
    let w, h, dpr, t = 0;
    function size() {
      dpr = Math.min(window.devicePixelRatio || 1, 2);
      w = canvas.clientWidth; h = canvas.clientHeight;
      canvas.width = w * dpr; canvas.height = h * dpr;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    }
    function frame() {
      ctx.clearRect(0, 0, w, h);
      const R = Math.min(w * 0.42, h * 1.15), cx = w / 2, cy = h + R * 0.35;
      const g = ctx.createRadialGradient(cx, cy, R * 0.2, cx, cy, R);
      g.addColorStop(0, "rgba(13,20,51,0.95)"); g.addColorStop(1, "rgba(25,31,110,0.9)");
      ctx.fillStyle = g; ctx.beginPath(); ctx.arc(cx, cy, R, 0, Math.PI * 2); ctx.fill();
      const a = t * 0.0009, ca = Math.cos(a), sa = Math.sin(a), tilt = 0.35, ct = Math.cos(tilt), st = Math.sin(tilt);
      for (const [x, y, z, k] of pts) {
        let X = x * ca + z * sa, Z = -x * sa + z * ca;
        let Y = y * ct - Z * st; Z = y * st + Z * ct;
        if (Z < -0.15) continue;
        const px = cx + X * R, py = cy - Y * R;
        if (py > h + 2) continue;
        const depth = (Z + 1) / 2;
        const twinkle = reduce ? 1 : 0.65 + 0.35 * Math.sin(t * 0.004 + k * 40);
        const mint = k > 0.82;
        ctx.fillStyle = mint ? `rgba(169,242,203,${Math.min(1, 1.2 * depth * twinkle)})` : `rgba(140,220,255,${Math.min(1, 1.05 * depth * twinkle)})`;
        const s = (mint ? 2.6 : 1.9) * (0.45 + depth);
        ctx.fillRect(px, py, s, s);
      }
      if (!reduce) { t += 16; requestAnimationFrame(frame); }
    }
    size(); window.addEventListener("resize", () => { size(); if (reduce) frame(); });
    frame();
  }

  window.ZollectArt = { mountAvatars, zoteArt, globe };
})();
