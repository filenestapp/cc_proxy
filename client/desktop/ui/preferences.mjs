export function createPreferenceMenu(details, onSelect) {
  const trigger = details.querySelector("summary");
  const choices = [...details.querySelectorAll("button[data-value]")];
  let selected = choices[0];

  function close(returnFocus) {
    details.open = false;
    if (returnFocus) trigger.focus();
  }

  details.addEventListener("toggle", () => {
    trigger.setAttribute("aria-expanded", String(details.open));
    if (details.open) selected.focus();
  });

  for (const choice of choices) {
    choice.addEventListener("click", () => {
      onSelect(choice.dataset.value);
      close(true);
    });
  }

  function closeOutside(event) {
    if (details.open && !details.contains(event.target)) close(false);
  }
  document.addEventListener("pointerdown", closeOutside);
  document.addEventListener("focusin", closeOutside);

  details.addEventListener("keydown", (event) => {
    if (event.key === "ArrowDown" || event.key === "ArrowUp") {
      event.preventDefault();
      if (!details.open) {
        details.open = true;
        return;
      }
      const index = choices.indexOf(document.activeElement);
      const step = event.key === "ArrowDown" ? 1 : -1;
      choices[(index + step + choices.length) % choices.length].focus();
    } else if (details.open && (event.key === "Home" || event.key === "End")) {
      event.preventDefault();
      (event.key === "Home" ? choices[0] : choices.at(-1)).focus();
    } else if (details.open && event.key === "Escape") {
      event.preventDefault();
      close(true);
    } else if (details.open && event.key === "Tab") {
      close(true);
    }
  });

  return {
    update(value, name) {
      selected = choices.find((choice) => choice.dataset.value === value) ?? choices[0];
      for (const choice of choices) {
        choice.setAttribute("aria-checked", String(choice === selected));
      }
      const label = name + " · " + selected.textContent.trim();
      trigger.setAttribute("aria-label", label);
      trigger.title = label;
    },
  };
}
