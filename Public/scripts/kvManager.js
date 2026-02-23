const updateKvFormEl = document.getElementById("updateKvForm");
const getKvFormEl = document.getElementById("getKvForm");
const deleteKvFormEl = document.getElementById("deleteKvForm");
const refreshKvButtonEl = document.getElementById("refreshKvButton");

const updateKeyEl = document.getElementById("updateKey");
const updateValueEl = document.getElementById("updateValue");
const getKeyEl = document.getElementById("getKey");
const deleteKeyEl = document.getElementById("deleteKey");

const kvStatusEl = document.getElementById("kvStatus");
const kvListEl = document.getElementById("kvList");
const kvOutputEl = document.getElementById("kvOutput");

function setStatus(message, isError = false) {
  if (!kvStatusEl) return;
  kvStatusEl.textContent = message;
  kvStatusEl.classList.toggle("text-red-600", isError);
  kvStatusEl.classList.toggle("text-gray-700", !isError);
}

function setOutput(payload) {
  if (!kvOutputEl) return;
  kvOutputEl.textContent = JSON.stringify(payload, null, 2);
}

function renderList(items) {
  if (!kvListEl) return;
  kvListEl.innerHTML = "";

  if (!items || items.length === 0) {
    const empty = document.createElement("li");
    empty.className = "text-sm text-gray-500";
    empty.textContent = "No entries yet.";
    kvListEl.appendChild(empty);
    return;
  }

  items.forEach((item) => {
    const row = document.createElement("li");
    row.className =
      "flex items-center justify-between rounded-lg border border-gray-200 bg-slate-50 px-3 py-2";

    const label = document.createElement("p");
    label.className = "text-sm text-gray-900 truncate";
    label.textContent = `${item.key}: ${item.value}`;

    const action = document.createElement("button");
    action.type = "button";
    action.className =
      "rounded-md border border-red-200 px-3 py-1 text-xs font-medium text-red-700 hover:bg-red-50";
    action.textContent = "Delete";
    action.dataset.deleteKey = item.key;

    row.appendChild(label);
    row.appendChild(action);
    kvListEl.appendChild(row);
  });
}

function normalizeKey(raw) {
  return (raw || "").trim();
}

async function callJSON(url, method, body) {
  const response = await fetch(url, {
    method,
    headers: { "Content-Type": "application/json" },
    body: body ? JSON.stringify(body) : undefined,
  });

  let json = null;
  try {
    json = await response.json();
  } catch (_) {
    json = null;
  }

  if (!response.ok) {
    const reason =
      json && json.reason ? json.reason : `Request failed (${response.status})`;
    throw new Error(reason);
  }

  return json;
}

async function refreshList() {
  setStatus("Loading entries...");
  const response = await callJSON("/api/kv", "GET");
  renderList(response.items || []);
  setOutput(response);
  setStatus(`Loaded ${(response.items || []).length} entries.`);
}

async function updateEntry() {
  const key = normalizeKey(updateKeyEl?.value);
  const value = updateValueEl?.value ?? "";
  if (!key) throw new Error("Update key is required.");

  setStatus(`Updating "${key}"...`);
  const response = await callJSON(
    `/api/kv/${encodeURIComponent(key)}`,
    "POST",
    {
      value,
    },
  );
  setOutput(response);
  setStatus(`Updated "${key}".`);
  await refreshList();
}

async function getEntry() {
  const key = normalizeKey(getKeyEl?.value);
  if (!key) throw new Error("Get key is required.");

  setStatus(`Fetching "${key}"...`);
  const response = await callJSON(`/api/kv/${encodeURIComponent(key)}`, "GET");
  setOutput(response);
  setStatus(`Fetched "${key}".`);
}

async function deleteEntry(rawKey) {
  const key = normalizeKey(rawKey);
  if (!key) throw new Error("Delete key is required.");

  setStatus(`Deleting "${key}"...`);
  const response = await callJSON(
    `/api/kv/${encodeURIComponent(key)}`,
    "DELETE",
  );
  setOutput(response);
  setStatus(`Deleted "${key}".`);
  await refreshList();
}

async function withErrorHandling(task, fallbackMessage) {
  try {
    await task();
  } catch (error) {
    setStatus(error.message || fallbackMessage, true);
    setOutput({ error: String(error) });
  }
}

if (updateKvFormEl) {
  updateKvFormEl.addEventListener("submit", async (event) => {
    event.preventDefault();
    await withErrorHandling(updateEntry, "Update failed.");
  });
}

if (getKvFormEl) {
  getKvFormEl.addEventListener("submit", async (event) => {
    event.preventDefault();
    await withErrorHandling(getEntry, "Get failed.");
  });
}

if (deleteKvFormEl) {
  deleteKvFormEl.addEventListener("submit", async (event) => {
    event.preventDefault();
    const key = normalizeKey(deleteKeyEl?.value);
    await withErrorHandling(() => deleteEntry(key), "Delete failed.");
  });
}

if (refreshKvButtonEl) {
  refreshKvButtonEl.addEventListener("click", async () => {
    await withErrorHandling(refreshList, "Refresh failed.");
  });
}

if (kvListEl) {
  kvListEl.addEventListener("click", async (event) => {
    const target = event.target;
    if (!(target instanceof HTMLElement)) return;

    const key = target.dataset.deleteKey;
    if (!key) return;

    const shouldDelete = window.confirm(`Delete "${key}"?`);
    if (!shouldDelete) return;

    await withErrorHandling(() => deleteEntry(key), "Delete failed.");
  });
}

void withErrorHandling(refreshList, "Failed to load entries.");
