// The one screen this app ships itself. Everything else is the dashboard, served by the
// in-process server. This only appears when there is no Ferryman folder to show.
"use strict";

const $ = (id) => document.getElementById(id);
const invoke = (cmd) => window.__TAURI__.core.invoke(cmd);

function text(parent, tag, content) {
  const el = document.createElement(tag);
  el.textContent = content;
  parent.appendChild(el);
  return el;
}

function render(state) {
  const body = $("body");
  body.replaceChildren();
  $("err").textContent = "";
  const button = $("action");
  button.disabled = false;
  if (state.state === "no_projects") {
    $("title").textContent = "Ferryman is set up, with no projects yet";
    text(body, "p", "Your Ferryman folder is ready at " + state.path + ".");
    const p = text(body, "p", "To add a project, open a terminal in its folder and run ");
    text(p, "code", "ferry enable");
    p.append(". Then come back here.");
    button.textContent = "Check again";
    button.onclick = () => run("check_again");
  } else {
    $("title").textContent = "No Ferryman found on this computer";
    text(body, "p", "Ferryman keeps its channels and project copies in one folder. There isn't one here yet.");
    text(body, "p", "Setting up makes that folder in your home directory. Nothing you already have is moved.");
    button.textContent = "Set up Ferryman on this computer";
    button.onclick = () => run("set_up_here");
  }
}

async function run(command) {
  const button = $("action");
  button.disabled = true;
  try {
    render(JSON.parse(await invoke(command)));
  } catch (error) {
    button.disabled = false;
    $("err").textContent = String(error);
  }
}

render({ state: new URLSearchParams(location.search).get("state") || "no_root", path: new URLSearchParams(location.search).get("path") || "" });
