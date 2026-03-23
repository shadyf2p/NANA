import "./style.css";
import { GetServerURL, OpenInBrowser } from "../wailsjs/go/main/App";

document.querySelector("#app").innerHTML = `
  <div class="shell">
    <header class="topbar">
      <div>
        <div class="title">Admin Portal Wails</div>
        <div class="sub">Desktop wrapper for CSS admin UI</div>
      </div>
      <div class="actions">
        <button id="btnReload">Reload</button>
        <button id="btnOpenBrowser">Open Browser</button>
      </div>
    </header>
    <main class="content">
      <div id="loading" class="loading">Dang ket noi admin server...</div>
      <iframe id="panel" class="panel" title="Admin Portal"></iframe>
    </main>
  </div>
`;

const loadingEl = document.getElementById("loading");
const panelEl = document.getElementById("panel");
const btnReload = document.getElementById("btnReload");
const btnOpenBrowser = document.getElementById("btnOpenBrowser");

async function init() {
  const url = await GetServerURL();
  panelEl.src = url;
  panelEl.onload = () => {
    loadingEl.style.display = "none";
    panelEl.style.opacity = "1";
  };
  btnReload.onclick = () => {
    loadingEl.style.display = "block";
    panelEl.style.opacity = "0";
    panelEl.src = `${url}?t=${Date.now()}`;
  };
  btnOpenBrowser.onclick = async () => {
    await OpenInBrowser();
  };
}

init().catch((err) => {
  loadingEl.textContent = `Khong the khoi tao: ${err?.message || err}`;
});
