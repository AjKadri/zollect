(function () {
  const { mountAvatars, zoteArt } = window.ZollectArt;
  const SERIALS = { 1: "6a44a03186657519", 2: "0fea744310c8f3f0", 3: "6de2c6b676700d2c" };
  const EXPLORER = "https://mainnet.zcashexplorer.app/transactions/";

  /* Real mainnet results, used only if the live checker can't be reached. */
  const RECORDED = {
    verify: `FINAL txid=d44ab08a9c212509ad0e88bba0d82f6183ae1852404e67c47dbb435a3fbd61ec action=0 height=3531330
ITEM 1 VALID txid=abfb41a26bc70de6484f7b8edf4828ef079b4b8fda2857cb1858ee79130cfbda action=2
ITEM 2 VALID txid=4971340fa5620a37ddd84b1b1890c3b8c24958100173e8fabb65ccf41ea4cca7 action=2
ITEM 3 VALID txid=9ec4773a8828fac9dfd7a141a0294dbdbe338d263555080ddcaae3ff369fa060 action=0
SUPPLY SEALED count=3
VERIFY_TIMING mode=verify-any-item tx_count=6 elapsed_ms=1341`,
    attacks: {
      "old-proof": `SPENT collection=lagos-lights item=2 hop=1 txid=2a4f5bae61ad39f8f3bfa674c9fc1377eb8a3668451f96f2ca00c1e1355f0a14 action=1 spending_txid=c08b51eeffce637bb62d7ab309956bff21c98e99715031526d7edf2a494cdda0
VERIFY_TIMING mode=challenge-proof tx_count=7 elapsed_ms=1398`,
    },
    held: `HELD collection=lagos-lights item=2 hop=2 txid=c08b51eeffce637bb62d7ab309956bff21c98e99715031526d7edf2a494cdda0 action=1 control_signature=VALID
VERIFY_TIMING mode=challenge-proof tx_count=7 elapsed_ms=4890`,
  };

  const ITEMS_FALLBACK = [1, 2, 3].map((n) => ({ item: n, label: `Lagos Lights #${n}`, txids: [] }));

  const STEPS = [
    { title: "Lagos Lights is minted and sealed", body: "Three zotes are created, then the collection is sealed so no more can ever be added.", txid: "d44ab08a9c212509ad0e88bba0d82f6183ae1852404e67c47dbb435a3fbd61ec", chips: [["valid", "3 genuine"], ["valid", "Supply sealed"]] },
    { title: "Tobi receives zote #2", body: "The zote moves into Tobi's own vault. Only his key can spend it.", txid: "2a4f5bae61ad39f8f3bfa674c9fc1377eb8a3668451f96f2ca00c1e1355f0a14", chips: [["held", "Tobi holds"]] },
    { title: "Kemi buys it in one transaction", body: "Kemi builds the sale, Tobi checks his payment and signs last. Zote and ZEC move together, or not at all.", txid: "c08b51eeffce637bb62d7ab309956bff21c98e99715031526d7edf2a494cdda0", chips: [["valid", "0.0002 ZEC paid"]] },
    { title: "The old proof stops working", body: "Tobi's proof now shows spent. Kemi's shows held. The checker links her zote back to the sealed mint.", txid: null, chips: [["spent", "Tobi: spent"], ["held", "Kemi: held"], ["valid", "Link valid"]] },
  ];

  let live = true;

  async function post(path, body) {
    const res = await fetch(path, { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify(body) });
    const data = await res.json().catch(() => ({}));
    if (!res.ok && !data.output) throw new Error(data.error || `The checker answered ${res.status}.`);
    return data;
  }

  function parse(output = "") {
    const lines = output.split("\n");
    const timing = output.match(/elapsed_ms=(\d+)/);
    return {
      valid: lines.filter((l) => /^ITEM \d+ VALID/.test(l)).map((l) => l.match(/^ITEM (\d+)/)[1]),
      sealed: /SUPPLY SEALED/.test(output),
      held: /^HELD/m.test(output),
      spent: /^SPENT/m.test(output),
      fail: (output.match(/FAIL[^\n]*/) || [null])[0],
      ms: timing ? Number(timing[1]) : null,
    };
  }

  function chip(kind, text) {
    const s = document.createElement("span");
    s.className = `chip chip-${kind}`;
    s.textContent = text;
    return s;
  }

  function verdict(el, output, { item, recorded }) {
    const p = parse(output);
    el.hidden = false;
    el.classList.toggle("is-error", Boolean(p.fail));
    el.replaceChildren();
    const head = document.createElement("div");
    head.className = "verdict-head";
    if (p.fail) head.append(chip("spent", "Check failed"));
    else {
      if (p.valid.includes(String(item))) head.append(chip("valid", "Genuine"));
      if (p.sealed) head.append(chip("valid", "Collection sealed"));
      if (p.held) head.append(chip("held", "Held"));
    }
    if (p.ms !== null) {
      const t = document.createElement("span");
      t.className = "time";
      t.textContent = `${(p.ms / 1000).toFixed(1)} s, two servers agreed`;
      head.append(t);
    }
    el.append(head);
    const ul = document.createElement("ul");
    const say = (txt) => { const li = document.createElement("li"); li.textContent = txt; ul.append(li); };
    if (p.fail) say(p.fail.replace(/^FAIL\s*/, "Reason: "));
    else {
      say(`Zote #${item} traces back to the Lagos Lights mint.`);
      if (p.sealed) say("No zote can ever be added after the seal.");
      if (recorded) say("Recorded mainnet result. The live checker isn't reachable from this preview.");
    }
    el.append(ul);
    const d = document.createElement("details");
    const s = document.createElement("summary");
    s.textContent = "Show the checker's output";
    const pre = document.createElement("pre");
    pre.textContent = output;
    d.append(s, pre);
    el.append(d);
  }

  function renderItem(item) {
    const n = Number(item.item);
    const card = document.createElement("article");
    card.className = "zote-card" + (n === 2 ? " is-featured" : "");
    const art = document.createElement("div");
    art.className = "zote-art";
    art.innerHTML = zoteArt(n);
    if (n === 2) art.append(chip("held", "Held by Kemi"));
    const seal = document.createElement("img"); seal.className = "seal-sm"; seal.src = "logo.svg"; seal.alt = ""; seal.setAttribute("aria-hidden", "true"); art.append(seal);
    const body = document.createElement("div");
    body.className = "zote-body";
    const title = document.createElement("div");
    title.className = "zote-title";
    const h = document.createElement("h3");
    h.textContent = item.label || `Lagos Lights #${n}`;
    const meta = document.createElement("span");
    meta.textContent = n === 2 ? "2 owners so far" : "Unsold";
    title.append(h, meta);
    const serial = document.createElement("p"); serial.className = "zote-serial";
    serial.textContent = (SERIALS[n] || "").toUpperCase().replace(/(.{4})/g, "$1 ").trim();
    const btn = document.createElement("button");
    btn.className = "btn btn-line";
    btn.type = "button";
    btn.textContent = `Verify #${n}`;
    const out = document.createElement("div");
    out.className = "verdict";
    out.hidden = true;
    out.setAttribute("aria-live", "polite");
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      btn.textContent = "Asking two servers…";
      try {
        if (!live) throw new Error("offline");
        const r = await post("/api/verify-item", { item: n });
        verdict(out, r.output ?? `FAIL ${r.error ?? "No result from the checker."}`, { item: n });
      } catch (e) {
        if (!live) verdict(out, RECORDED.verify, { item: n, recorded: true });
        else verdict(out, `FAIL ${e.message}`, { item: n });
      } finally {
        btn.disabled = false;
        btn.textContent = `Verify #${n} again`;
      }
    });
    body.append(title, serial, btn, out);
    card.append(art, body);
    return card;
  }

  function renderTimeline() {
    const ol = document.getElementById("timeline");
    STEPS.forEach((s) => {
      const li = document.createElement("li");
      const main = document.createElement("div");
      const h = document.createElement("h3"); h.textContent = s.title;
      const p = document.createElement("p"); p.textContent = s.body;
      const chips = document.createElement("div"); chips.className = "chips";
      s.chips.forEach(([k, t]) => chips.append(chip(k, t)));
      main.append(h, p, chips);
      li.append(main);
      if (s.txid) {
        const a = document.createElement("a");
        a.className = "tx"; a.href = EXPLORER + s.txid; a.target = "_blank"; a.rel = "noopener";
        a.textContent = `View on explorer (${s.txid.slice(0, 8)}…)`;
        li.append(a);
      }
      ol.append(li);
    });
  }

  function newCode() {
    const a = new Uint8Array(6); crypto.getRandomValues(a);
    return Array.from(a, (b) => b.toString(16).padStart(2, "0")).join("").replace(/(.{4})/g, "$1 ").trim();
  }

  function setupChallenge(item) {
    const btn = document.getElementById("challenge-button");
    const box = document.getElementById("challenge-result");
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      box.replaceChildren();
      const l1 = document.createElement("p"); l1.className = "step-label"; l1.textContent = "Your challenge code";
      const code = document.createElement("p"); code.className = "code"; code.textContent = "…";
      const l2 = document.createElement("p"); l2.className = "step-label"; l2.textContent = "Kemi's wallet is answering…";
      box.append(l1, code, l2);
      let output, challenge, recorded = false;
      try {
        if (!live) throw new Error("offline");
        const r = await post("/api/challenge", { item });
        challenge = r.challenge; output = r.output ?? `FAIL ${r.error ?? "No answer."}`;
      } catch (e) {
        if (!live) { challenge = newCode(); output = RECORDED.held; recorded = true; }
        else { output = `FAIL ${e.message}`; }
      }
      code.textContent = challenge || "not issued";
      const p = parse(output);
      l2.textContent = p.held ? "Kemi answered" : "No valid answer";
      const res = document.createElement("div");
      res.className = "verdict" + (p.fail ? " is-error" : "");
      const head = document.createElement("div"); head.className = "verdict-head";
      head.append(p.held ? chip("held", "Held by the person who answered") : chip("spent", p.spent ? "Spent" : "Not proven"));
      if (p.ms !== null) { const t = document.createElement("span"); t.className = "time"; t.textContent = `${(p.ms / 1000).toFixed(1)} s`; head.append(t); }
      res.append(head);
      const msg = document.createElement("ul");
      const li = document.createElement("li");
      li.textContent = p.fail ? p.fail.replace(/^FAIL\s*/, "Reason: ")
        : recorded ? "Recorded mainnet answer. The live service isn't reachable from this preview."
        : "Signed for your code just now, and checked against two Zcash servers.";
      msg.append(li); res.append(msg);
      const d = document.createElement("details"); const s = document.createElement("summary"); s.textContent = "Show the checker's output";
      const pre = document.createElement("pre"); pre.textContent = output; d.append(s, pre); res.append(d);
      box.append(res);
      btn.disabled = false;
      btn.textContent = "Send another challenge";
    });
  }

  function tilt() {
    const stage = document.getElementById("stage"), stack = document.getElementById("stack");
    if (!stage || window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    window.addEventListener("pointermove", (e) => {
      const x = e.clientX / window.innerWidth - 0.5, y = e.clientY / window.innerHeight - 0.5;
      stack.style.transform = `rotateX(${18 - y * 10}deg) rotateY(${-22 + x * 16}deg) rotateZ(-6deg)`;
    });
  }

  function scrollMotion() {
    if (window.matchMedia("(prefers-reduced-motion: reduce)").matches) return;
    const stack = document.getElementById("stack");
    const sale = document.getElementById("sale");
    const cast = sale.querySelector(".cast");
    const tl = document.getElementById("timeline");
    sale.classList.add("is-scrubbing"); tl.classList.add("is-scrubbing");
    let ticking = false;
    function update() {
      ticking = false;
      const vh = window.innerHeight;
      const lift = Math.min(1, Math.max(0, window.scrollY / (vh * 0.7)));
      stack.style.setProperty("--lift", lift.toFixed(3));
      const r = cast.getBoundingClientRect();
      const p = Math.min(1, Math.max(0, (vh * 0.85 - r.top) / (vh * 0.6)));
      sale.style.setProperty("--p", p.toFixed(3));
      tl.querySelectorAll("li").forEach((li) => {
        li.classList.toggle("is-on", li.getBoundingClientRect().top < vh * 0.75);
      });
    }
    window.addEventListener("scroll", () => { if (!ticking) { ticking = true; requestAnimationFrame(update); } }, { passive: true });
    update();
  }

  const ATTACK_TEXT = {
    "old-proof": (p) => p.spent ? "Rejected: that zote was spent in the sale. Tobi's proof no longer works." : null,
    "forged-signature": (p) => p.fail ? "Rejected: the signature doesn't match the zote's key." : null,
    "wrong-key": (p) => p.fail ? "Rejected: that key never owned zote #2." : null,
  };

  function setupAttacks() {
    document.querySelectorAll(".attack").forEach((card) => {
      const kind = card.dataset.kind, btn = card.querySelector("button"), out = card.querySelector(".verdict");
      const label = btn.textContent;
      btn.addEventListener("click", async () => {
        btn.disabled = true; btn.textContent = "Asking the checker…";
        let output = null, recorded = false;
        try {
          if (!live) throw new Error("offline");
          const r = await post("/api/attack", { kind });
          output = r.output ?? `FAIL ${r.error ?? "No result."}`;
        } catch (e) {
          if (!live && RECORDED.attacks[kind]) { output = RECORDED.attacks[kind]; recorded = true; }
          else if (!live) { output = null; }
          else output = `FAIL ${e.message}`;
        }
        out.hidden = false; out.replaceChildren();
        const head = document.createElement("div"); head.className = "verdict-head";
        const ul = document.createElement("ul"); const li = document.createElement("li");
        if (output === null) {
          head.append(chip("valid", "Live check only"));
          li.textContent = "This attack runs only against the live checker, which isn't reachable from this preview.";
        } else {
          const p = parse(output);
          const recognised = p.spent || Boolean(p.fail);
          head.append(recognised ? chip("held", "Blocked") : chip("spent", "Checker error, try again"));
          if (p.ms !== null) { const t = document.createElement("span"); t.className = "time"; t.textContent = `${(p.ms / 1000).toFixed(1)} s`; head.append(t); }
          li.textContent = (!recognised ? "Checker error, try again" : (ATTACK_TEXT[kind](p) || (p.fail ? p.fail.replace(/^FAIL\s*/, "Reason: ") : "Unexpected result: see the output.")))
            + (recorded ? " (Recorded mainnet result.)" : "");
          const d = document.createElement("details"); const sm = document.createElement("summary"); sm.textContent = "Show the checker's output";
          const pre = document.createElement("pre"); pre.textContent = output; d.append(sm, pre);
          ul.append(li); out.append(head, ul, d);
          btn.disabled = false; btn.textContent = label; return;
        }
        ul.append(li); out.append(head, ul);
        btn.disabled = false; btn.textContent = label;
      });
    });
  }

  async function load() {
    mountAvatars();
    tilt();
    renderTimeline();
    scrollMotion();
    setupAttacks();
    const na = document.getElementById("note-art"); if (na) na.innerHTML = zoteArt(2);
    let items = ITEMS_FALLBACK, holderItem = 2;
    try {
      const res = await fetch("/api/collection");
      if (!res.ok) throw new Error();
      const data = await res.json();
      if (Array.isArray(data.items) && data.items.length) items = data.items;
      if (data.challengeItem) holderItem = Number(data.challengeItem);
      ["repo", "evidence", "video"].forEach((k) => {
        const link = document.getElementById(`${k}-link`);
        if (link && data.links?.[k]) link.href = data.links[k];
      });
    } catch {
      live = false;
      const note = document.getElementById("mode-note");
      note.hidden = false;
      note.textContent = "Preview mode: the live checker isn't reachable here, so buttons show the recorded mainnet results.";
    }
    document.getElementById("items").replaceChildren(...items.map(renderItem));
    setupChallenge(holderItem);
  }

  load();
})();
