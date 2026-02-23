(function (global) {
  const ns = (global.PasskeyTest = global.PasskeyTest || {});

  function setPasskeysStatus(ctx, message, isError = false) {
    if (!ctx.passkeysStatusEl) return;
    ctx.passkeysStatusEl.textContent = message;
    ctx.passkeysStatusEl.classList.toggle("text-red-600", isError);
    ctx.passkeysStatusEl.classList.toggle("text-gray-600", !isError);
  }

  function formatCredentialID(credentialID) {
    if (!credentialID) return "";
    if (credentialID.length <= 18) return credentialID;
    return `${credentialID.slice(0, 8)}...${credentialID.slice(-8)}`;
  }

  function renderPasskeys(ctx, passkeys) {
    if (!ctx.passkeysListEl) return;
    ctx.passkeysListEl.innerHTML = "";

    if (!passkeys || passkeys.length === 0) {
      const item = document.createElement("li");
      item.className = "text-sm text-gray-500";
      item.textContent = "No passkeys found.";
      ctx.passkeysListEl.appendChild(item);
      return;
    }

    passkeys.forEach((passkey) => {
      const item = document.createElement("li");
      item.className =
        "flex items-center justify-between gap-3 rounded-lg border border-gray-200 bg-white px-3 py-2";

      const details = document.createElement("div");
      details.className = "min-w-0";

      const name = document.createElement("p");
      name.className = "truncate text-sm font-medium text-gray-900";
      name.textContent = passkey.name || "Unnamed passkey";

      const credential = document.createElement("p");
      credential.className = "truncate text-xs text-gray-500";
      credential.textContent = formatCredentialID(passkey.id);

      details.appendChild(name);
      details.appendChild(credential);

      const deleteButton = document.createElement("button");
      deleteButton.type = "button";
      deleteButton.className =
        "rounded-md border border-red-200 px-3 py-1 text-xs font-medium text-red-700 hover:bg-red-50";
      deleteButton.textContent = "Delete";
      deleteButton.dataset.passkeyDelete = passkey.id;
      deleteButton.dataset.passkeyName = passkey.name || "this passkey";

      item.appendChild(details);
      item.appendChild(deleteButton);
      ctx.passkeysListEl.appendChild(item);
    });
  }

  async function fetchPasskeys(ctx) {
    if (!ctx.passkeysListEl) return;
    setPasskeysStatus(ctx, "Loading passkeys...");
    const response = await ns.callJSON("/passkeys", "GET");
    renderPasskeys(ctx, response.passkeys || []);
    setPasskeysStatus(ctx, `Passkeys: ${(response.passkeys || []).length}`);
  }

  async function deletePasskey(ctx, credentialID, passkeyName) {
    if (!credentialID) return;
    setPasskeysStatus(ctx, `Deleting "${passkeyName}" ...`);
    const response = await ns.callJSON(
      `/passkeys/${encodeURIComponent(credentialID)}`,
      "DELETE",
    );
    renderPasskeys(ctx, response.passkeys || []);
    setPasskeysStatus(ctx, `Deleted. Passkeys: ${(response.passkeys || []).length}`);
  }

  ns.createPasskeysManager = function createPasskeysManager(ctx) {
    return {
      bind() {
        if (ctx.refreshPasskeysButtonEl) {
          ctx.refreshPasskeysButtonEl.addEventListener("click", async () => {
            await ns.withErrorHandling(
              ctx,
              () => fetchPasskeys(ctx),
              "Failed to refresh passkeys.",
            );
          });
        }

        if (ctx.passkeysListEl) {
          ctx.passkeysListEl.addEventListener("click", async (event) => {
            const target = event.target;
            if (!(target instanceof HTMLElement)) return;

            const credentialID = target.dataset.passkeyDelete;
            if (!credentialID) return;

            const passkeyName = target.dataset.passkeyName || "this passkey";
            const shouldDelete = window.confirm(`Delete "${passkeyName}"?`);
            if (!shouldDelete) return;

            await ns.withErrorHandling(
              ctx,
              () => deletePasskey(ctx, credentialID, passkeyName),
              "Failed to delete passkey.",
            );
          });

          void ns.withErrorHandling(
            ctx,
            () => fetchPasskeys(ctx),
            "Failed to load passkeys.",
          );
        }
      },
      syncFromContinue(continueResponse) {
        if (!continueResponse || !Array.isArray(continueResponse.passkeys)) return;
        renderPasskeys(ctx, continueResponse.passkeys);
        setPasskeysStatus(ctx, `Passkeys: ${continueResponse.passkeys.length}`);
      },
    };
  };
})(window);
