// Sin handlers inline: compatible con CSP script-src 'self'.

// 1) Mostrar/ocultar contraseña
document.addEventListener("click", function (event) {
  var toggle = event.target.closest("[data-toggle-password]");
  if (!toggle) return;
  var input = document.getElementById(toggle.getAttribute("data-toggle-password"));
  if (!input) return;
  var show = input.type === "password";
  input.type = show ? "text" : "password";
  toggle.textContent = show ? "Ocultar" : "Mostrar";
  toggle.setAttribute("aria-pressed", show ? "true" : "false");
});

// 2) Diálogos: <button commandfor="id" command="show-modal|close"> es nativo en navegadores
//    modernos; este respaldo cubre los que aún no lo soportan.
if (!("commandForElement" in HTMLButtonElement.prototype)) {
  document.addEventListener("click", function (event) {
    var button = event.target.closest("button[commandfor]");
    if (!button) return;
    var dialog = document.getElementById(button.getAttribute("commandfor"));
    if (!dialog || typeof dialog.showModal !== "function") return;
    var command = button.getAttribute("command");
    if (command === "show-modal") dialog.showModal();
    else if (command === "close") dialog.close();
  });
}

// 3) Cerrar un diálogo al hacer clic fuera de su contenido
document.addEventListener("click", function (event) {
  var dialog = event.target;
  if (dialog instanceof HTMLDialogElement && dialog.open) dialog.close();
});

// 4) Menú lateral (botón ☰): en escritorio se oculta/muestra y se recuerda; en móvil es un panel superpuesto.
(function () {
  var app = document.getElementById("app");
  var button = document.getElementById("menu-btn");
  if (!app || !button) return;
  var desktop = window.matchMedia("(min-width: 56rem)");

  function isOpen() {
    var state = app.getAttribute("data-nav");
    return desktop.matches ? state !== "closed" : state === "open";
  }
  function render() {
    button.setAttribute("aria-expanded", isOpen() ? "true" : "false");
  }
  function setNav(open) {
    app.setAttribute("data-nav", open ? "open" : "closed");
    if (desktop.matches) {
      try { localStorage.setItem("nav", open ? "open" : "closed"); } catch (e) { /* sin almacenamiento */ }
    }
    render();
  }
  function applySaved() {
    if (!desktop.matches) return;
    try {
      if (localStorage.getItem("nav") === "closed") app.setAttribute("data-nav", "closed");
    } catch (e) { /* sin almacenamiento */ }
  }

  button.addEventListener("click", function () { setNav(!isOpen()); });
  document.addEventListener("click", function (event) {
    if (event.target.closest("[data-nav-close]") || (!desktop.matches && event.target.closest(".sidebar a"))) {
      setNav(false);
    }
  });
  document.addEventListener("keydown", function (event) {
    if (event.key === "Escape" && !desktop.matches && isOpen()) {
      setNav(false);
      button.focus();
    }
  });
  desktop.addEventListener("change", function () {
    app.removeAttribute("data-nav");
    applySaved();
    render();
  });
  applySaved();
  render();
})();

// 5) Cerrar el menú de usuario al hacer clic fuera
document.addEventListener("click", function (event) {
  document.querySelectorAll("details.usermenu[open]").forEach(function (menu) {
    if (!menu.contains(event.target)) menu.removeAttribute("open");
  });
});
