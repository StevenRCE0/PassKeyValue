(function () {
  const ns = window.PasskeyTest;
  const form = document.getElementById("allow");
  if (!form) return;

  const ctx = { statusEl: document.getElementById("status") };
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    ns.withErrorHandling(
      ctx,
      async () => {
        ns.setStatus(ctx, "Waiting for your passkey…");
        const publicKey = ns.decodeRequestOptions(JSON.parse(form.dataset.options));
        const credential = await navigator.credentials.get({ publicKey });
        form.elements.credential.value = JSON.stringify(ns.authenticationPayload(credential));
        form.submit();
      },
      "Approval failed.",
    );
  });
})();
