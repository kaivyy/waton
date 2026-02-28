let activeChatJid = null;
let chatCache = [];

async function getJSON(url, options = {}) {
  const res = await fetch(url, {
    headers: { "Content-Type": "application/json" },
    ...options
  });
  const data = await res.json();
  if (!res.ok) {
    throw new Error(data.error || `Request failed: ${res.status}`);
  }
  return data;
}

function formatTime(ts) {
  const date = new Date(ts || Date.now());
  return date.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" });
}

function escapeHtml(value) {
  return String(value || "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function autoResizeComposer() {
  const textEl = document.getElementById("send-text");
  textEl.style.height = "auto";
  textEl.style.height = `${Math.min(textEl.scrollHeight, 120)}px`;
}

function updateComposerState() {
  const textEl = document.getElementById("send-text");
  const sendBtn = document.getElementById("send-btn");
  const hasChat = Boolean(activeChatJid);
  sendBtn.disabled = !hasChat;
  textEl.placeholder = hasChat ? "Type a message" : "Select a chat first";
}

function setStatusBadge(state) {
  const pill = document.getElementById("status-pill");
  const status = state.status || state.state || "disconnected";
  pill.textContent = status;
  pill.className = `status ${status}`;
}

function setHeaderChatInfo(jid) {
  const titleEl = document.getElementById("chat-title");
  const subtitleEl = document.getElementById("chat-subtitle");
  if (!jid) {
    titleEl.textContent = "No chat selected";
    subtitleEl.textContent = "Connect WhatsApp and pick a chat.";
    return;
  }
  const chat = chatCache.find((item) => item.jid === jid);
  titleEl.textContent = chat ? chat.title : jid;
  subtitleEl.textContent = jid;
}

function setQrPanel(state) {
  const panel = document.getElementById("qr-panel");
  const qrText = document.getElementById("qr-text");
  const qrImage = document.getElementById("qr-image");

  if (state.status === "connecting" && state.qr) {
    panel.classList.add("visible");
    qrText.value = state.qr;
    if (state.qr_image_data_url) {
      qrImage.src = state.qr_image_data_url;
      qrImage.style.display = "block";
    } else {
      qrImage.removeAttribute("src");
      qrImage.style.display = "none";
    }
    return;
  }

  panel.classList.remove("visible");
  qrText.value = "";
  qrImage.removeAttribute("src");
}

function renderChatList(chats) {
  const listEl = document.getElementById("chat-list");
  const query = document.getElementById("chat-search").value.trim().toLowerCase();
  const filtered = chats.filter((chat) => {
    if (!query) return true;
    return (
      (chat.title || "").toLowerCase().includes(query) ||
      (chat.jid || "").toLowerCase().includes(query) ||
      (chat.last_text || "").toLowerCase().includes(query)
    );
  });

  if (!filtered.length) {
    listEl.innerHTML = "<div class='chat-item'><div class='chat-preview'>No chats yet.</div></div>";
    return;
  }

  listEl.innerHTML = filtered
    .map((chat) => {
      const unread = Number(chat.unread_count || 0);
      const unreadTag = unread > 0 ? `<span class="chat-unread">${unread}</span>` : "";
      const activeClass = chat.jid === activeChatJid ? "active" : "";
      return `
        <article class="chat-item ${activeClass}" data-jid="${chat.jid}">
          <div class="chat-row">
            <div class="chat-title">${escapeHtml(chat.title || chat.jid)}</div>
            <div class="chat-time">${chat.last_timestamp ? formatTime(chat.last_timestamp) : ""}</div>
          </div>
          <div class="chat-row">
            <div class="chat-preview">${escapeHtml(chat.last_text || "")}</div>
            ${unreadTag}
          </div>
        </article>
      `;
    })
    .join("");

  listEl.querySelectorAll(".chat-item[data-jid]").forEach((node) => {
    node.addEventListener("click", async () => {
      const jid = node.getAttribute("data-jid");
      await openChat(jid);
    });
  });
}

function renderThread(messages) {
  const threadEl = document.getElementById("message-thread");
  const previousLastId = threadEl.dataset.lastMessageId || "";
  const wasNearBottom = threadEl.scrollHeight - threadEl.scrollTop - threadEl.clientHeight < 80;
  if (!messages.length) {
    threadEl.innerHTML = "<div class='chat-preview'>No messages in this chat yet.</div>";
    threadEl.dataset.lastMessageId = "";
    return;
  }

  const lastMessage = messages[messages.length - 1] || {};
  const nextLastId = String(lastMessage.id || "");
  threadEl.innerHTML = messages
    .map((msg) => `
      <div class="msg-row ${msg.from_me ? "out" : "in"}">
        <div class="bubble">
          <div class="bubble-text">${escapeHtml(msg.text || "")}</div>
          <div class="bubble-meta">${formatTime(msg.timestamp)} - ${escapeHtml(msg.status || "")}</div>
        </div>
      </div>
    `)
    .join("");

  threadEl.dataset.lastMessageId = nextLastId;
  if (wasNearBottom || nextLastId !== previousLastId) {
    threadEl.scrollTop = threadEl.scrollHeight;
  }
}

async function refreshConnectionState() {
  const state = await getJSON("/api/connection");
  setStatusBadge(state);
  setQrPanel(state);
  return state;
}

async function refreshChats() {
  const data = await getJSON("/api/chats");
  chatCache = data.chats || [];
  renderChatList(chatCache);
}

async function openChat(chatJid) {
  activeChatJid = chatJid;
  setHeaderChatInfo(chatJid);
  updateComposerState();
  await getJSON(`/api/chats/${encodeURIComponent(chatJid)}/read`, { method: "POST" });
  const data = await getJSON(`/api/chats/${encodeURIComponent(chatJid)}/messages`);
  renderThread(data.messages || []);
  renderChatList(chatCache);
}

async function refreshActiveThread() {
  if (!activeChatJid) {
    renderThread([]);
    return;
  }
  const data = await getJSON(`/api/chats/${encodeURIComponent(activeChatJid)}/messages`);
  renderThread(data.messages || []);
}

async function connectWhatsapp() {
  try {
    await getJSON("/api/connect", { method: "POST" });
    await refreshConnectionState();
  } catch (err) {
    alert(err.message);
  }
}

async function disconnectWhatsapp() {
  try {
    await getJSON("/api/disconnect", { method: "POST" });
    await refreshConnectionState();
  } catch (err) {
    alert(err.message);
  }
}

async function sendMessage() {
  if (!activeChatJid) {
    alert("Select a chat first.");
    return;
  }
  const textEl = document.getElementById("send-text");
  const text = textEl.value.trim();
  if (!text) return;
  try {
    await getJSON("/api/send", {
      method: "POST",
      body: JSON.stringify({ to: activeChatJid, text })
    });
    textEl.value = "";
    autoResizeComposer();
    await refreshChats();
    await refreshActiveThread();
  } catch (err) {
    alert(err.message);
  }
}

async function openNewChatFromInput() {
  const raw = document.getElementById("new-chat-jid").value.trim();
  if (!raw) return;
  const jid = raw.includes("@") ? raw : `${raw}@s.whatsapp.net`;
  activeChatJid = jid;
  setHeaderChatInfo(jid);
  updateComposerState();
  renderThread([]);
}

async function init() {
  document.getElementById("connect-btn").addEventListener("click", connectWhatsapp);
  document.getElementById("disconnect-btn").addEventListener("click", disconnectWhatsapp);
  document.getElementById("send-btn").addEventListener("click", sendMessage);
  document.getElementById("open-chat-btn").addEventListener("click", openNewChatFromInput);
  document.getElementById("chat-search").addEventListener("input", () => renderChatList(chatCache));
  document.getElementById("send-text").addEventListener("input", autoResizeComposer);
  document.getElementById("send-text").addEventListener("keydown", (event) => {
    if (event.key === "Enter" && !event.shiftKey) {
      event.preventDefault();
      void sendMessage();
    }
  });

  await refreshConnectionState();
  await refreshChats();
  setHeaderChatInfo(activeChatJid);
  updateComposerState();
  renderThread([]);
  autoResizeComposer();

  setInterval(async () => {
    await refreshConnectionState();
    await refreshChats();
    await refreshActiveThread();
  }, 2200);
}

init().catch((err) => alert(`Dashboard init failed: ${err.message}`));
