(function () {
  const ns = window.PasskeyTest;
  const form = document.getElementById("allow");
  const signup = document.getElementById("signup");
  if (!form) return;

  const ctx = { statusEl: document.getElementById("status") };
  const ticket = form.elements.ticket.value;

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

  signup.addEventListener("submit", (event) => {
    event.preventDefault();
    ns.withErrorHandling(
      ctx,
      async () => {
        ns.setStatus(ctx, "Creating your passkey…");
        const started = await ns.callJSON("/authorize/signup", "POST", {
          ticket,
          name: signup.elements.name.value,
        });
        const publicKey = ns.decodeCreationOptions(started.options);
        const credential = await navigator.credentials.create({ publicKey });
        const scopes = [...document.querySelectorAll(".scope-choice:checked")].map((box) => box.value);
        const answer = await ns.callJSON("/authorize/signup/finish", "POST", {
          ticket,
          signup: started.ticket,
          credential: ns.registrationPayload(credential),
          scopes,
        });
        window.location.href = answer.redirect;
      },
      "Sign-up failed.",
    );
  });
})();
