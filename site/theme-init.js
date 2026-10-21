(function () {
  try {
    var saved = localStorage.getItem("rehub.theme");
    if (saved === "light" || saved === "dark") document.documentElement.setAttribute("data-theme", saved);
  } catch (err) {
    /* storage can be blocked; the default dark theme applies */
  }
})();
