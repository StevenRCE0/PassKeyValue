(function (global) {
  const ns = (global.PasskeyTest = global.PasskeyTest || {});

  function setAuthStep(ctx, showDetails) {
    if (ctx.authChoiceFormEl) {
      ctx.authChoiceFormEl.classList.toggle("hidden", showDetails);
    }
    if (ctx.authFormEl) {
      ctx.authFormEl.classList.toggle("hidden", !showDetails);
    }
  }

  function setMergeStep(ctx, showDetails) {
    if (ctx.mergeChoiceFormEl) {
      ctx.mergeChoiceFormEl.classList.toggle("hidden", showDetails);
    }
    if (ctx.mergeFormEl) {
      ctx.mergeFormEl.classList.toggle("hidden", !showDetails);
    }
  }

  function syncAuthModeVisibility(ctx) {
    if (!ctx.modeEl || !ctx.authPasskeyNameContainerEl) return;
    const isRegistration = ctx.modeEl.value === ns.STAGE_REGISTRATION;
    ctx.authPasskeyNameContainerEl.classList.toggle("hidden", !isRegistration);
  }

  function syncMergeModeVisibility(ctx) {
    if (!ctx.mergeBModeEl || !ctx.mergePasskeyNameContainerEl) return;
    const isRegistration = ctx.mergeBModeEl.value === ns.STAGE_REGISTRATION;
    ctx.mergePasskeyNameContainerEl.classList.toggle("hidden", !isRegistration);
  }

  async function runBeginContinue(ctx, mode, passkeyName) {
    await ns.runPasskeyFlow(ctx, {
      stage: mode,
      isMerging: false,
      passkeyName,
      beginStatus: "Running /begin ...",
      credentialStatus:
        mode === ns.STAGE_REGISTRATION
          ? "Creating registration credential ..."
          : "Requesting authentication assertion ...",
      continueStatus:
        mode === ns.STAGE_REGISTRATION
          ? "Running /continue for registration ..."
          : "Running /continue for authentication ...",
      successStatus:
        mode === ns.STAGE_REGISTRATION
          ? "Registration flow complete."
          : "Authentication flow complete.",
      expectedStageError: "Unexpected /begin response shape.",
      onSuccess: () => {
        window.location.assign("/private");
      },
    });
  }

  async function runMerge(ctx, action, mergeMode, passkeyName) {
    if (action === ns.STAGE_REGISTRATION) {
      await ns.runPasskeyFlow(ctx, {
        stage: ns.STAGE_REGISTRATION,
        isMerging: true,
        passkeyName,
        beginStatus: "Running /begin for session flow ...",
        credentialStatus: "Creating passkey B ...",
        continueStatus: "Running /continue for B registration ...",
        successStatus: "Session flow complete (created passkey B).",
        expectedStageError: "Create B flow must return registration options.",
      });
      return;
    }

    await ns.runPasskeyFlow(ctx, {
      stage: ns.STAGE_AUTHENTICATION,
      isMerging: true,
      beginStatus: "Running /begin for session flow ...",
      credentialStatus: "Select existing passkey B ...",
      continueStatus: "Running /continue for merge ...",
      successStatus: "Session flow complete (provided passkey B).",
      continueExtras: { mergeMode },
      expectedStageError:
        "Provide B flow must return authentication request options.",
    });
  }

  ns.createAuthMergeManager = function createAuthMergeManager(ctx) {
    return {
      bind() {
        if (ctx.authFormEl) {
          ctx.authFormEl.addEventListener("submit", async (event) => {
            event.preventDefault();
            const mode = ctx.modeEl ? ctx.modeEl.value : ns.STAGE_REGISTRATION;
            const passkeyName = ctx.passkeyNameEl ? ctx.passkeyNameEl.value : "";
            await ns.withErrorHandling(
              ctx,
              () => runBeginContinue(ctx, mode, passkeyName),
              "Authentication flow failed.",
            );
          });
        }

        if (ctx.mergeFormEl) {
          ctx.mergeFormEl.addEventListener("submit", async (event) => {
            event.preventDefault();
            const action = ctx.mergeBModeEl
              ? ctx.mergeBModeEl.value
              : ns.STAGE_REGISTRATION;
            const mergeMode = ctx.mergeModeEl
              ? ctx.mergeModeEl.value
              : "keepCurrentUser";
            const passkeyName = ctx.mergePasskeyNameEl
              ? ctx.mergePasskeyNameEl.value
              : "";
            await ns.withErrorHandling(
              ctx,
              () => runMerge(ctx, action, mergeMode, passkeyName),
              "Merge flow failed.",
            );
          });
        }

        if (ctx.modeEl && ctx.authModeButtons.length > 0) {
          ctx.authModeButtons.forEach((button) => {
            button.addEventListener("click", async () => {
              const selectedMode = button.getAttribute("data-auth-mode");
              if (!selectedMode) return;
              ctx.modeEl.value = selectedMode;

              if (selectedMode === ns.STAGE_AUTHENTICATION) {
                setAuthStep(ctx, false);
                await ns.withErrorHandling(
                  ctx,
                  () => runBeginContinue(ctx, ns.STAGE_AUTHENTICATION, ""),
                  "Authentication flow failed.",
                );
                return;
              }

              syncAuthModeVisibility(ctx);
              setAuthStep(ctx, true);
            });
          });

          setAuthStep(ctx, false);
          syncAuthModeVisibility(ctx);
        }

        if (ctx.authBackButtonEl) {
          ctx.authBackButtonEl.addEventListener("click", () => {
            ns.clearFeedback(ctx);
            setAuthStep(ctx, false);
          });
        }

        if (ctx.mergeBModeEl && ctx.mergeActionButtons.length > 0) {
          ctx.mergeActionButtons.forEach((button) => {
            button.addEventListener("click", async () => {
              const selectedAction = button.getAttribute("data-merge-action");
              if (!selectedAction) return;
              ctx.mergeBModeEl.value = selectedAction;

              if (selectedAction !== ns.STAGE_REGISTRATION) {
                setMergeStep(ctx, false);
                const mergeMode = ctx.mergeModeEl
                  ? ctx.mergeModeEl.value
                  : "keepCurrentUser";
                await ns.withErrorHandling(
                  ctx,
                  () =>
                    runMerge(ctx, ns.STAGE_AUTHENTICATION, mergeMode, ""),
                  "Merge flow failed.",
                );
                return;
              }

              syncMergeModeVisibility(ctx);
              setMergeStep(ctx, true);
            });
          });

          setMergeStep(ctx, false);
          syncMergeModeVisibility(ctx);
        }

        if (ctx.mergeBackButtonEl) {
          ctx.mergeBackButtonEl.addEventListener("click", () => {
            ns.clearFeedback(ctx);
            setMergeStep(ctx, false);
          });
        }
      },
    };
  };
})(window);
