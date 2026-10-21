import { h } from "./dom.js";
import { moonIcon, sunIcon } from "./icons.js";

export function currentTheme() {
  return document.documentElement.getAttribute("data-theme") === "light" ? "light" : "dark";
}

export function setTheme(theme) {
  document.documentElement.setAttribute("data-theme", theme);
  try {
    localStorage.setItem("rehub.theme", theme);
  } catch (err) {
    /* the choice just will not persist */
  }
}

export function themeButton() {
  const button = h("button", { class: "btn ghost iconbtn", type: "button" });
  const draw = () => {
    const light = currentTheme() === "light";
    button.replaceChildren(light ? moonIcon() : sunIcon());
    button.setAttribute("aria-label", light ? "Switch to dark mode" : "Switch to light mode");
    button.setAttribute("title", light ? "Switch to dark mode" : "Switch to light mode");
  };
  button.addEventListener("click", () => {
    setTheme(currentTheme() === "light" ? "dark" : "light");
    draw();
  });
  draw();
  return button;
}
