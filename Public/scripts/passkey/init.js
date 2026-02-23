(function (global) {
  const ns = global.PasskeyTest;
  if (!ns) return;

  const ctx = {
    authChoiceFormEl: document.getElementById("authChoiceForm"),
    authFormEl: document.getElementById("authForm"),
    modeEl: document.getElementById("mode"),
    authModeButtons: document.querySelectorAll("[data-auth-mode]"),
    passkeyNameEl: document.getElementById("passkeyName"),
    authPasskeyNameContainerEl: document.getElementById(
      "authPasskeyNameContainer",
    ),
    authBackButtonEl: document.getElementById("authBackButton"),

    mergeChoiceFormEl: document.getElementById("mergeChoiceForm"),
    mergeFormEl: document.getElementById("mergeForm"),
    mergeBModeEl: document.getElementById("mergeBMode"),
    mergeModeEl: document.getElementById("mergeMode"),
    mergeActionButtons: document.querySelectorAll("[data-merge-action]"),
    mergePasskeyNameEl: document.getElementById("mergePasskeyName"),
    mergePasskeyNameContainerEl: document.getElementById(
      "mergePasskeyNameContainer",
    ),
    mergeBackButtonEl: document.getElementById("mergeBackButton"),

    passkeysListEl: document.getElementById("passkeysList"),
    passkeysStatusEl: document.getElementById("passkeysStatus"),
    refreshPasskeysButtonEl: document.getElementById("refreshPasskeysButton"),

    statusEl: document.getElementById("status"),
    outputEl: document.getElementById("output"),
  };

  if (ns.createPasskeysManager) {
    const passkeysManager = ns.createPasskeysManager(ctx);
    ctx.syncPasskeysFromContinue = passkeysManager.syncFromContinue;
    passkeysManager.bind();
  }

  if (ns.createAuthMergeManager) {
    const authMergeManager = ns.createAuthMergeManager(ctx);
    authMergeManager.bind();
  }
})(window);
