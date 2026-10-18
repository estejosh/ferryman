// The one screen this app ships itself. Everything else is the dashboard, served by the
// in-process server. This only appears when there is no Ferryman folder to show.
import { invoke } from "./vendor/tauri-api/core.js";

const $ = (id) => document.getElementById(id);

function text(parent, tag, content) {
  const el = document.createElement(tag);
  el.textContent = content;
  parent.appendChild(el);
  return el;
}

// "Make a new one" is a second, explicit choice, and asks once more: it repoints this
// computer at a different folder, which must never happen as a side effect of a retry.
let confirming = false;

function render(state) {
  const body = $("body");
  body.replaceChildren();
  $("err").textContent = "";
  const primary = $("action");
  const secondary = $("other");
  primary.disabled = false;
  secondary.hidden = true;
  secondary.disabled = false;

  if (state.state === "unreachable") {
    $("title").textContent = "Your Ferryman folder is not reachable";
    text(body, "p", "This computer is set up to use " + state.path + ", but it can't be reached right now. A drive may be unmounted or a network share offline.");
    text(body, "p", "Nothing has been changed. Reconnect it and try again.");
    primary.textContent = "Retry";
    primary.onclick = () => run("check_again", {});
    secondary.hidden = false;
    if (confirming) {
      text(body, "p", "This makes a new, empty Ferryman folder in your home directory and points this computer at it. Your old folder is left alone, but this computer will stop using it.");
      secondary.textContent = "Yes, make a new one here";
      secondary.onclick = () => { confirming = false; run("set_up_here", { replace: true }); };
    } else {
      secondary.textContent = "Make a new Ferryman folder here instead...";
      secondary.onclick = () => { confirming = true; render(state); };
    }
  } else if (state.state === "no_projects") {
    $("title").textContent = "Ferryman is set up, with no projects yet";
    text(body, "p", "Your Ferryman folder is ready at " + state.path + ".");
    const p = text(body, "p", "To add a project, open a terminal in its folder and run ");
    text(p, "code", "ferry enable");
    p.append(". Then come back here.");
    primary.textContent = "Check again";
    primary.onclick = () => run("check_again", {});
  } else {
    $("title").textContent = "No Ferryman found on this computer";
    text(body, "p", "Ferryman keeps its channels and project copies in one folder. There isn't one here yet.");
    text(body, "p", "Setting up makes that folder in your home directory. Nothing you already have is moved.");
    primary.textContent = "Set up Ferryman on this computer";
    primary.onclick = () => run("set_up_here", { replace: false });
  }
}

async function run(command, args) {
  $("action").disabled = true;
  $("other").disabled = true;
  try {
    render(JSON.parse(await invoke(command, args)));
  } catch (error) {
    $("action").disabled = false;
    $("other").disabled = false;
    $("err").textContent = String(error);
  }
}

const query = new URLSearchParams(location.search);
render({ state: query.get("state") || "no_root", path: query.get("path") || "" });
