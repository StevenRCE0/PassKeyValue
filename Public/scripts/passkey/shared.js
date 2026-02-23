(function (global) {
  const ns = (global.PasskeyTest = global.PasskeyTest || {});

  ns.DEFAULT_PASSKEY_NAME = "My Passkey";
  ns.STAGE_REGISTRATION = "registration";
  ns.STAGE_AUTHENTICATION = "authentication";

  ns.setStatus = function setStatus(ctx, message, isError = false) {
    if (!ctx.statusEl) return;
    ctx.statusEl.textContent = message;
    ctx.statusEl.classList.toggle("text-red-600", isError);
    ctx.statusEl.classList.toggle("text-green-700", !isError);
  };

  ns.setOutput = function setOutput(ctx, data) {
    if (!ctx.outputEl) return;
    ctx.outputEl.textContent = JSON.stringify(data, null, 2);
  };

  ns.clearFeedback = function clearFeedback(ctx) {
    if (ctx.statusEl) ctx.statusEl.textContent = "";
    if (ctx.outputEl) ctx.outputEl.textContent = "";
  };

  ns.withErrorHandling = async function withErrorHandling(
    ctx,
    task,
    fallbackMessage,
  ) {
    try {
      await task();
    } catch (error) {
      ns.setStatus(ctx, error.message || fallbackMessage, true);
      ns.setOutput(ctx, { error: String(error) });
    }
  };

  ns.callJSON = async function callJSON(url, method, body) {
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
  };

  ns.normalizePasskeyName = function normalizePasskeyName(name) {
    const normalized = (name || "").trim();
    return normalized || ns.DEFAULT_PASSKEY_NAME;
  };

  ns.ensureBeginResponse = function ensureBeginResponse(
    beginResponse,
    stage,
    optionsKey,
    errorMessage,
  ) {
    if (beginResponse.mode !== stage || !beginResponse[optionsKey]) {
      throw new Error(errorMessage);
    }
  };

  ns.decodeCreationOptions = function decodeCreationOptions(options) {
    options.challenge = bufferDecode(options.challenge);
    options.user.id = bufferDecode(options.user.id);

    if (options.excludeCredentials) {
      options.excludeCredentials = options.excludeCredentials.map(
        (credential) => ({
          id: bufferDecode(credential.id),
          type: credential.type,
          transports: credential.transports,
        }),
      );
    }

    return options;
  };

  ns.decodeRequestOptions = function decodeRequestOptions(options) {
    options.challenge = bufferDecode(options.challenge);

    if (options.allowCredentials) {
      options.allowCredentials = options.allowCredentials.map((credential) => ({
        id: bufferDecode(credential.id),
        type: credential.type,
        transports: credential.transports,
      }));
    }

    return options;
  };

  ns.registrationPayload = function registrationPayload(credential) {
    return {
      id: credential.id,
      rawId: bufferEncode(new Uint8Array(credential.rawId)),
      type: credential.type,
      response: {
        attestationObject: bufferEncode(
          new Uint8Array(credential.response.attestationObject),
        ),
        clientDataJSON: bufferEncode(
          new Uint8Array(credential.response.clientDataJSON),
        ),
      },
    };
  };

  ns.authenticationPayload = function authenticationPayload(credential) {
    const userHandle = credential.response.userHandle
      ? bufferEncode(new Uint8Array(credential.response.userHandle))
      : "";

    return {
      id: credential.id,
      rawId: bufferEncode(new Uint8Array(credential.rawId)),
      type: credential.type,
      response: {
        authenticatorData: bufferEncode(
          new Uint8Array(credential.response.authenticatorData),
        ),
        clientDataJSON: bufferEncode(
          new Uint8Array(credential.response.clientDataJSON),
        ),
        signature: bufferEncode(new Uint8Array(credential.response.signature)),
        userHandle,
      },
    };
  };

  ns.getFlowHandlers = function getFlowHandlers() {
    return {
      [ns.STAGE_REGISTRATION]: {
        optionsKey: "creationOptions",
        decodeOptions: ns.decodeCreationOptions,
        requestCredential: async (publicKey) =>
          navigator.credentials.create({ publicKey }),
        buildCredentialPayload: ns.registrationPayload,
      },
      [ns.STAGE_AUTHENTICATION]: {
        optionsKey: "requestOptions",
        decodeOptions: ns.decodeRequestOptions,
        requestCredential: async (publicKey) =>
          navigator.credentials.get({ publicKey }),
        buildCredentialPayload: ns.authenticationPayload,
      },
    };
  };

  ns.runPasskeyFlow = async function runPasskeyFlow(ctx, config) {
    const handlers = ns.getFlowHandlers();
    const handler = handlers[config.stage];
    const normalizedPasskeyName = ns.normalizePasskeyName(config.passkeyName);
    const isRegistration = config.stage === ns.STAGE_REGISTRATION;

    ns.setStatus(ctx, config.beginStatus);
    const beginPayload = {
      stage: config.stage,
      isMerging: config.isMerging,
      ...(config.beginExtras || {}),
    };

    if (isRegistration) {
      beginPayload.passkeyName = normalizedPasskeyName;
    }

    const beginResponse = await ns.callJSON("/begin", "POST", beginPayload);
    ns.ensureBeginResponse(
      beginResponse,
      config.stage,
      handler.optionsKey,
      config.expectedStageError,
    );

    const publicKey = handler.decodeOptions(beginResponse[handler.optionsKey]);
    ns.setStatus(ctx, config.credentialStatus);
    const credential = await handler.requestCredential(publicKey);

    ns.setStatus(ctx, config.continueStatus);
    const continuePayload = {
      credential: handler.buildCredentialPayload(credential),
      ...(config.continueExtras || {}),
    };

    if (isRegistration) {
      continuePayload.passkeyName = normalizedPasskeyName;
    }

    const continueResponse = await ns.callJSON(
      "/continue",
      "POST",
      continuePayload,
    );
    ns.setOutput(ctx, { beginResponse, continueResponse });
    ns.setStatus(ctx, config.successStatus);

    if (ctx.syncPasskeysFromContinue) {
      ctx.syncPasskeysFromContinue(continueResponse);
    }

    if (config.onSuccess) config.onSuccess({ beginResponse, continueResponse });
  };
})(window);
