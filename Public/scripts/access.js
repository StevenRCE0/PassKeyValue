(function () {
  const ns = window.PasskeyTest;
  const ctx = { statusEl: document.getElementById("status") };

  document.querySelectorAll("form[data-confirm-action]").forEach((form) => {
    form.addEventListener("submit", (event) => {
      event.preventDefault();
      if (!window.confirm(form.dataset.question)) return;
      ns.withErrorHandling(
        ctx,
        async () => {
          ns.setStatus(ctx, "Confirm with your passkey…");
          form.elements.confirmation.value = await ns.confirmWithPasskey(form.dataset.confirmAction);
          form.submit();
        },
        "Confirmation failed.",
      );
    });
  });
})();
