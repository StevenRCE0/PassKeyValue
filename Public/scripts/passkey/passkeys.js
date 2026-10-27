(function (global) {
  const ns = (global.PasskeyTest = global.PasskeyTest || {});

  function setPasskeysStatus(ctx, message, isError = false) {
    if (!ctx.passkeysStatusEl) return;
    ctx.passkeysStatusEl.textContent = message;
    ctx.passkeysStatusEl.classList.toggle("is-error", isError);
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
      item.className = "list-row text-sm muted";
      item.textContent = "No passkeys found.";
      ctx.passkeysListEl.appendChild(item);
      return;
    }

    passkeys.forEach((passkey) => {
      const item = document.createElement("li");
      item.className = "list-row";

      const details = document.createElement("div");
      details.className = "min-w-0";

      const name = document.createElement("p");
      name.className = "truncate text-sm font-medium";
      name.textContent = passkey.name || "Unnamed passkey";

      const credential = document.createElement("p");
      credential.className = "truncate text-xs muted";
      credential.textContent = formatCredentialID(passkey.id);

      details.appendChild(name);
      details.appendChild(credential);

      const deleteButton = document.createElement("button");
      deleteButton.type = "button";
      deleteButton.className = "btn-danger";
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
