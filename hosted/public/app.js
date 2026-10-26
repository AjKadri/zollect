const status = document.querySelector("#status");
const collectionName = document.querySelector("#collection-name");
const items = document.querySelector("#items");
const records = document.querySelector("#records");
const challengeButton = document.querySelector("#challenge-button");
const challengeResult = document.querySelector("#challenge-result");

function resultBlock(text) {
  const block = document.createElement("pre");
  block.className = "result";
  block.textContent = text;
  return block;
}

async function post(path, body) {
  const response = await fetch(path, {
    method: "POST",
    headers: { "content-type": "application/json" },
    body: JSON.stringify(body),
  });
  return response.json();
}

function renderItem(item) {
  const card = document.createElement("article");
  card.className = "item-card";
  const title = document.createElement("h3");
  title.textContent = item.label;
  const txids = document.createElement("p");
  txids.className = "muted mono";
  txids.textContent = `${item.txids.length} known transaction${item.txids.length === 1 ? "" : "s"}`;
  const button = document.createElement("button");
  button.className = "button secondary";
  button.textContent = "Verify item";
  const output = resultBlock("No verification run yet.");
  button.addEventListener("click", async () => {
    button.disabled = true;
    output.textContent = "Checking both servers…";
    try {
      const result = await post("/api/verify-item", { item: item.item });
      output.textContent = result.output ?? result.error ?? "No checker output";
    } catch (error) {
      output.textContent = error.message;
    } finally {
      button.disabled = false;
    }
  });
  card.append(title, txids, button, output);
  return card;
}

function renderRecords(values) {
  records.replaceChildren();
  if (!Array.isArray(values)) {
    records.append(resultBlock(JSON.stringify(values, null, 2)));
    return;
  }
  for (const value of values) {
    const row = document.createElement("article");
    row.className = "record";
    const title = document.createElement("h3");
    title.textContent = value.label ?? value.kind ?? "Record";
    const txid = document.createElement("p");
    txid.className = "mono";
    txid.textContent = value.txid ?? "No txid";
    const output = document.createElement("pre");
    output.textContent = value.output ?? "";
    row.append(title, txid, output);
    records.append(row);
  }
}

async function load() {
  try {
    const response = await fetch("/api/collection");
    const data = await response.json();
    collectionName.textContent = data.collection || "Unconfigured collection";
    items.replaceChildren(...(data.items ?? []).map(renderItem));
    renderRecords(data.records ?? []);
    challengeButton.disabled = !data.challengeAvailable;
    challengeButton.dataset.item = data.items?.[0]?.item ?? "";
    status.textContent = "Two-server read-only mode";
    status.classList.add("ready");
  } catch (error) {
    status.textContent = `Unavailable: ${error.message}`;
  }
}

challengeButton.addEventListener("click", async () => {
  challengeButton.disabled = true;
  challengeResult.textContent = "Issuing fresh challenge…";
  try {
    const result = await post("/api/challenge", { item: Number(challengeButton.dataset.item) });
    challengeResult.textContent = result.output
      ? `challenge=${result.challenge}\n${result.output}`
      : result.error ?? "No checker output";
  } catch (error) {
    challengeResult.textContent = error.message;
  } finally {
    challengeButton.disabled = false;
  }
});

load();
