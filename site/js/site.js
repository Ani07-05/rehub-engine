(function () {
  "use strict";
  var RAW = "https://raw.githubusercontent.com/Ani07-05/rehub-engine/main/scripts/install.sh";
  var root = document.documentElement;

  function currentTheme() {
    return root.getAttribute("data-theme") === "light" ? "light" : "dark";
  }
  function icon(kind) {
    var ns = "http://www.w3.org/2000/svg";
    var svg = document.createElementNS(ns, "svg");
    svg.setAttribute("width", "18");
    svg.setAttribute("height", "18");
    svg.setAttribute("viewBox", "0 0 20 20");
    svg.setAttribute("fill", "none");
    svg.setAttribute("stroke", "currentColor");
    svg.setAttribute("stroke-width", "1.4");
    svg.setAttribute("stroke-linecap", "round");
    svg.setAttribute("aria-hidden", "true");
    if (kind === "moon") {
      var m = document.createElementNS(ns, "path");
      m.setAttribute("d", "M16.5 12.2A6.8 6.8 0 0 1 7.8 3.5a6.8 6.8 0 1 0 8.7 8.7z");
      svg.appendChild(m);
    } else {
      var c = document.createElementNS(ns, "circle");
      c.setAttribute("cx", "10"); c.setAttribute("cy", "10"); c.setAttribute("r", "3.6");
      svg.appendChild(c);
      for (var i = 0; i < 8; i++) {
        var a = (i * Math.PI) / 4;
        var p = document.createElementNS(ns, "path");
        p.setAttribute("d", "M" + (10 + Math.cos(a) * 6.2) + " " + (10 + Math.sin(a) * 6.2) + "L" + (10 + Math.cos(a) * 8.4) + " " + (10 + Math.sin(a) * 8.4));
        svg.appendChild(p);
      }
    }
    return svg;
  }

  var themeBtn = document.getElementById("theme");
  function drawTheme() {
    if (!themeBtn) return;
    var light = currentTheme() === "light";
    themeBtn.replaceChildren(icon(light ? "moon" : "sun"));
    themeBtn.setAttribute("aria-label", light ? "Switch to dark mode" : "Switch to light mode");
    themeBtn.setAttribute("title", light ? "Switch to dark mode" : "Switch to light mode");
  }
  if (themeBtn) themeBtn.addEventListener("click", function () {
    var next = currentTheme() === "light" ? "dark" : "light";
    root.setAttribute("data-theme", next);
    try { localStorage.setItem("rehub.theme", next); } catch (err) { /* choice just will not persist */ }
    drawTheme();
  });
  drawTheme();

  var served = location.protocol === "http:" || location.protocol === "https:";
  if (served && location.hostname !== "raw.githubusercontent.com") {
    var url = location.origin + "/install.sh";
    document.querySelectorAll("pre code").forEach(function (el) {
      if (el.textContent.indexOf(RAW) !== -1) el.textContent = el.textContent.split(RAW).join(url);
    });
  }

  var tabs = Array.prototype.slice.call(document.querySelectorAll("[role=tab]"));
  function select(tab) {
    tabs.forEach(function (t) {
      var on = t === tab;
      t.setAttribute("aria-selected", on ? "true" : "false");
      t.tabIndex = on ? 0 : -1;
      document.getElementById(t.getAttribute("aria-controls")).hidden = !on;
    });
  }
  tabs.forEach(function (tab, i) {
    tab.addEventListener("click", function () { select(tab); });
    tab.addEventListener("keydown", function (e) {
      if (e.key !== "ArrowRight" && e.key !== "ArrowLeft") return;
      var next = tabs[(i + (e.key === "ArrowRight" ? 1 : tabs.length - 1)) % tabs.length];
      select(next);
      next.focus();
    });
  });

  var status = document.getElementById("copied");
  var timer = null;
  function say(text) {
    if (!status) return;
    status.textContent = text;
    clearTimeout(timer);
    timer = setTimeout(function () { status.textContent = ""; }, 3000);
  }
  function fallbackCopy(node) {
    var range = document.createRange();
    range.selectNodeContents(node);
    var sel = window.getSelection();
    sel.removeAllRanges();
    sel.addRange(range);
    var ok = false;
    try { ok = document.execCommand("copy"); } catch (err) { ok = false; }
    sel.removeAllRanges();
    return ok;
  }
  document.querySelectorAll("[data-copy]").forEach(function (button) {
    button.addEventListener("click", function () {
      var node = document.getElementById(button.getAttribute("data-copy"));
      var text = node.textContent;
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(text).then(function () { say("Copied."); }, function () {
          say(fallbackCopy(node) ? "Copied." : "Select the command and copy it.");
        });
      } else {
        say(fallbackCopy(node) ? "Copied." : "Select the command and copy it.");
      }
    });
  });
})();
