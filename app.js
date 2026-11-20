// Usuarios ficticios de prueba (Anexo C del informe)
const USUARIOS = {
  "estudiante.prueba@virginiogomez.cl": { pass: "Demo2026*", rol: "Reportante", nombre: "Estudiante Prueba" },
  "tecnico.prueba@virginiogomez.cl": { pass: "Tecnico2026*", rol: "Resolutor", nombre: "Técnico Mantención" },
  "admin.prueba@virginiogomez.cl": { pass: "Admin2026*", rol: "Administrador", nombre: "Jefatura Operaciones" }
};

let usuarioActual = null;

// Inicializar datos ficticios en localStorage si está vacío
function inicializarDatos() {
  if (!localStorage.getItem("arreglacampus_tickets")) {
    const iniciales = [
      {
        id: 100,
        ubicacion: "Sala 204",
        categoria: "Eléctrico",
        descripcion: "Proyector no enciende y enchufe sin corriente.",
        urgencia: "Crítico",
        estado: "Pendiente",
        autor: "docente@virginiogomez.cl",
        fechaCreacion: Date.now() - 120 * 60000, // Hace 2 horas
        foto: null
      }
    ];
    localStorage.setItem("arreglacampus_tickets", JSON.stringify(iniciales));
  }
}

function obtenerTickets() {
  return JSON.parse(localStorage.getItem("arreglacampus_tickets") || "[]");
}

function guardarTickets(tickets) {
  localStorage.setItem("arreglacampus_tickets", JSON.stringify(tickets));
}

// Sanitización básica contra inyección XSS (RNF-03 / CP-12)
function sanitizarTexto(texto) {
  const div = document.createElement("div");
  div.textContent = texto;
  return div.innerHTML;
}

function autocompletar(email, pass) {
  document.getElementById("login-email").value = email;
  document.getElementById("login-pass").value = pass;
}

// RNF-03: Autenticación institucional
document.getElementById("form-login").addEventListener("submit", function (e) {
  e.preventDefault();
  const email = document.getElementById("login-email").value.trim().toLowerCase();
  const pass = document.getElementById("login-pass").value;
  const errorBox = document.getElementById("login-error");

  // Validar dominio institucional
  if (!email.endsWith("@virginiogomez.cl") && !email.endsWith("@instituto.cl")) {
    errorBox.textContent = "Acceso denegado: Solo se permiten correos institucionales (@virginiogomez.cl o @instituto.cl).";
    errorBox.classList.remove("hidden");
    return;
  }

  const user = USUARIOS[email];
  if (!user || user.pass !== pass) {
    errorBox.textContent = "Credenciales incorrectas. Verifica tu correo o contraseña.";
    errorBox.classList.remove("hidden");
    return;
  }

  errorBox.classList.add("hidden");
  usuarioActual = { email, ...user };
  mostrarInterfazPorRol();
});

function mostrarInterfazPorRol() {
  document.getElementById("vista-login").classList.add("hidden");
  document.getElementById("user-nav").classList.remove("hidden");
  document.getElementById("user-badge").textContent = `${usuarioActual.nombre} (${usuarioActual.rol})`;

  if (usuarioActual.rol === "Reportante") {
    document.getElementById("vista-reportante").classList.remove("hidden");
    document.getElementById("vista-mantencion").classList.add("hidden");
    cambiarTabReportante("nuevo");
  } else {
    document.getElementById("vista-reportante").classList.add("hidden");
    document.getElementById("vista-mantencion").classList.remove("hidden");
    if (usuarioActual.rol === "Administrador") {
      document.getElementById("panel-metricas").classList.remove("hidden");
    } else {
      document.getElementById("panel-metricas").classList.add("hidden");
    }
    renderizarBandejaMantencion();
  }
}

function cerrarSesion() {
  usuarioActual = null;
  document.getElementById("vista-login").classList.remove("hidden");
  document.getElementById("vista-reportante").classList.add("hidden");
  document.getElementById("vista-mantencion").classList.add("hidden");
  document.getElementById("user-nav").classList.add("hidden");
  document.getElementById("form-login").reset();
}

function cambiarTabReportante(tab) {
  const panelNuevo = document.getElementById("panel-nuevo-reporte");
  const panelMis = document.getElementById("panel-mis-reportes");
  const btnNuevo = document.getElementById("tab-nuevo");
  const btnMis = document.getElementById("tab-mis");

  if (tab === "nuevo") {
    panelNuevo.classList.remove("hidden");
    panelMis.classList.add("hidden");
    btnNuevo.className = "px-4 py-2 bg-blue-700 text-white rounded-lg text-sm font-medium";
    btnMis.className = "px-4 py-2 bg-white text-slate-700 border border-slate-300 rounded-lg text-sm font-medium";
  } else {
    panelNuevo.classList.add("hidden");
    panelMis.classList.remove("hidden");
    btnMis.className = "px-4 py-2 bg-blue-700 text-white rounded-lg text-sm font-medium";
    btnNuevo.className = "px-4 py-2 bg-white text-slate-700 border border-slate-300 rounded-lg text-sm font-medium";
    renderizarMisReportes();
  }
}

// Validación de tamaño de imagen (Límite 10 MB - CP-03)
document.getElementById("rep-foto").addEventListener("change", function (e) {
  const file = e.target.files[0];
  const estado = document.getElementById("foto-estado");
  if (!file) {
    estado.textContent = "";
    return;
  }
  const sizeMB = (file.size / (1024 * 1024)).toFixed(2);
  if (file.size > 10 * 1024 * 1024) {
    estado.textContent = `Error: El archivo pesa ${sizeMB} MB y supera el límite de 10 MB.`;
    estado.className = "text-xs text-red-600 font-semibold mt-1";
    e.target.value = "";
  } else {
    estado.textContent = `Imagen lista (${sizeMB} MB) - Optimizada para envío.`;
    estado.className = "text-xs text-emerald-600 mt-1";
  }
});

// RF-01, RF-03, RF-06: Creación de incidente y bloqueo de duplicados
document.getElementById("form-reporte").addEventListener("submit", function (e) {
  e.preventDefault();
  const ubicacion = document.getElementById("rep-ubicacion").value;
  const categoria = document.getElementById("rep-categoria").value;
  const descripcionRaw = document.getElementById("rep-descripcion").value.trim();
  const urgencia = document.querySelector('input[name="urgencia"]:checked').value;
  const fotoInput = document.getElementById("rep-foto");

  // Validar campos obligatorios (CP-04)
  if (!ubicacion || !categoria || !descripcionRaw) {
    mostrarAlertaReporte("error", "Completa todos los campos obligatorios (Ubicación, Categoría y Descripción).");
    return;
  }

  const tickets = obtenerTickets();
  const ahora = Date.now();
  const SESENTA_MINUTOS = 60 * 60 * 1000;

  // RF-06: Regla anti-duplicidad (misma ubicación + categoría activa en < 60 min)
  const duplicado = tickets.find(t =>
    t.ubicacion === ubicacion &&
    t.categoria === categoria &&
    (t.estado === "Pendiente" || t.estado === "En Proceso") &&
    (ahora - t.fechaCreacion) < SESENTA_MINUTOS
  );

  if (duplicado) {
    mostrarAlertaReporte(
      "error",
      `Ya existe un reporte activo (#${duplicado.id}) para ${ubicacion} - ${categoria} creado hace menos de 60 minutos.`
    );
    return;
  }

  // Crear nuevo ticket (RF-01)
  const nuevoId = tickets.length > 0 ? Math.max(...tickets.map(t => t.id)) + 1 : 101;
  const nuevoTicket = {
    id: nuevoId,
    ubicacion,
    categoria,
    descripcion: sanitizarTexto(descripcionRaw),
    urgencia,
    estado: "Pendiente",
    autor: usuarioActual.email,
    fechaCreacion: ahora,
    foto: fotoInput.files[0] ? fotoInput.files[0].name : null
  };

  tickets.unshift(nuevoTicket);
  guardarTickets(tickets);

  // RF-03: Alerta por prioridad crítica
  let msgExito = `Ticket #${nuevoId} creado correctamente con estado Pendiente.`;
  if (urgencia === "Crítico") {
    msgExito += " Se ha enviado una alerta automática por correo al Administrador.";
  }

  mostrarAlertaReporte("exito", msgExito);
  document.getElementById("form-reporte").reset();
  document.getElementById("foto-estado").textContent = "";
});

function mostrarAlertaReporte(tipo, mensaje) {
  const box = document.getElementById("alerta-reporte");
  box.textContent = mensaje;
  box.classList.remove("hidden", "bg-red-50", "border-red-600", "text-red-700", "bg-emerald-50", "border-emerald-600", "text-emerald-700");

  if (tipo === "error") {
    box.classList.add("bg-red-50", "border-red-600", "text-red-700");
  } else {
    box.classList.add("bg-emerald-50", "border-emerald-600", "text-emerald-700");
  }
}

// RF-04: Consulta de Mis Reportes
function renderizarMisReportes() {
  const contenedor = document.getElementById("lista-mis-reportes");
  const misTickets = obtenerTickets().filter(t => t.autor === usuarioActual.email);

  if (misTickets.length === 0) {
    contenedor.innerHTML = `<p class="text-sm text-slate-500 bg-white p-4 rounded-lg border">Aún no has creado reportes.</p>`;
    return;
  }

  contenedor.innerHTML = misTickets.map(t => `
    <div class="bg-white p-4 rounded-xl shadow-sm border border-slate-200 flex justify-between items-start">
      <div>
        <div class="flex items-center gap-2 mb-1">
          <span class="font-bold text-slate-800">#${t.id} - ${t.ubicacion}</span>
          <span class="text-xs px-2 py-0.5 rounded bg-slate-100 text-slate-700 border">${t.categoria}</span>
          ${badgeUrgencia(t.urgencia)}
        </div>
        <p class="text-sm text-slate-600">${t.descripcion}</p>
        <p class="text-xs text-slate-400 mt-1">Creado: ${new Date(t.fechaCreacion).toLocaleString()}</p>
      </div>
      <span class="text-xs font-semibold px-2.5 py-1 rounded-full ${colorEstado(t.estado)}">
        ${t.estado}
      </span>
    </div>
  `).join("");
}

// RF-02 & RF-05: Bandeja de Mantención y Filtros
function renderizarBandejaMantencion() {
  // Control de acceso por rol (RNF-03 / CP-11)
  if (!usuarioActual || (usuarioActual.rol !== "Resolutor" && usuarioActual.rol !== "Administrador")) {
    alert("Error 403: Acceso denegado.");
    return;
  }

  const todos = obtenerTickets();
  const filtroUrgencia = document.getElementById("filtro-urgencia").value;
  const filtroEstado = document.getElementById("filtro-estado").value;

  // Actualizar métricas de Administrador
  document.getElementById("stat-total").textContent = todos.length;
  document.getElementById("stat-pendientes").textContent = todos.filter(t => t.estado === "Pendiente").length;
  document.getElementById("stat-criticos").textContent = todos.filter(t => t.urgencia === "Crítico" && t.estado !== "Resuelto").length;
  document.getElementById("stat-resueltos").textContent = todos.filter(t => t.estado === "Resuelto").length;

  const filtrados = todos.filter(t => {
    const cumpleUrg = filtroUrgencia === "TODOS" || t.urgencia === filtroUrgencia;
    const cumpleEst = filtroEstado === "TODOS" || t.estado === filtroEstado;
    return cumpleUrg && cumpleEst;
  });

  const contenedor = document.getElementById("lista-mantencion");
  if (filtrados.length === 0) {
    contenedor.innerHTML = `<p class="text-sm text-slate-500 bg-white p-4 rounded-lg border">No hay tickets que coincidan con los filtros seleccionados.</p>`;
    return;
  }

  contenedor.innerHTML = filtrados.map(t => `
    <div class="bg-white p-4 rounded-xl shadow-sm border border-slate-200 flex flex-col sm:flex-row justify-between gap-4">
      <div>
        <div class="flex items-center gap-2 mb-1">
          ${badgeUrgencia(t.urgencia)}
          <span class="font-bold text-slate-800">#${t.id} - ${t.ubicacion} (${t.categoria})</span>
        </div>
        <p class="text-sm text-slate-700">${t.descripcion}</p>
        <p class="text-xs text-slate-400 mt-1">Reportado por: ${t.autor} • ${new Date(t.fechaCreacion).toLocaleString()}</p>
      </div>
      <div class="flex items-center gap-2 self-end sm:self-center">
        <select onchange="cambiarEstadoTicket(${t.id}, this.value)" class="text-xs font-semibold px-2.5 py-1.5 rounded-lg border border-slate-300 bg-slate-50">
          <option value="Pendiente" ${t.estado === "Pendiente" ? "selected" : ""}>Pendiente</option>
          <option value="En Proceso" ${t.estado === "En Proceso" ? "selected" : ""}>En Proceso</option>
          <option value="Resuelto" ${t.estado === "Resuelto" ? "selected" : ""}>Resuelto</option>
          <option value="Rechazado" ${t.estado === "Rechazado" ? "selected" : ""}>Rechazado</option>
        </select>
      </div>
    </div>
  `).join("");
}

function cambiarEstadoTicket(id, nuevoEstado) {
  const tickets = obtenerTickets();
  const ticket = tickets.find(t => t.id === id);
  if (ticket) {
    ticket.estado = nuevoEstado;
    guardarTickets(tickets);
    renderizarBandejaMantencion();
  }
}

function badgeUrgencia(urg) {
  if (urg === "Crítico") return `<span class="text-xs font-bold px-2 py-0.5 rounded bg-red-600 text-white">CRÍTICO</span>`;
  if (urg === "Media") return `<span class="text-xs font-bold px-2 py-0.5 rounded bg-amber-500 text-white">MEDIA</span>`;
  return `<span class="text-xs font-bold px-2 py-0.5 rounded bg-emerald-600 text-white">BAJA</span>`;
}

function colorEstado(est) {
  if (est === "Pendiente") return "bg-amber-100 text-amber-800";
  if (est === "En Proceso") return "bg-blue-100 text-blue-800";
  if (est === "Resuelto") return "bg-emerald-100 text-emerald-800";
  return "bg-red-100 text-red-800";
}

inicializarDatos();