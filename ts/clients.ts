interface Row {
  hwaddr: string;
  in_rate: number;
  out_rate: number;
  name: string;
  ip: string;
  manufacturer: string;
}

var orderBy = "ip";

export const setOrderBy = (o: string) => {
  orderBy = o;
  updateData();
};

const fmtRate = function (bytes: number, decimals = 2): string {
  if (bytes < 0.01) return "";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  const v = parseFloat((bytes / Math.pow(k, i)).toFixed(dm));
  return `${v} ${sizes[i]}/s`;
};

const updateData = async () => {
  const resp = await fetch(`/v1/stats/?order_by=${orderBy}`);
  const data: Array<Row> = await resp.json();

  const el = document.createElement("tbody");
  const header = document.createElement("tr");
  header.innerHTML = `
<th><button onclick="app.setOrderBy('ip')">IP</a></th>
<th><button onclick="app.setOrderBy('name')">Hostname</a></th>
<th><button onclick="app.setOrderBy('rate_in')">IN rate</a></th>
<th><button onclick="app.setOrderBy('rate_out')">OUT rate</a></th>
<th><button onclick="app.setOrderBy('hwaddr')">MAC</a></th>
<th><button onclick="app.setOrderBy('manufacturer')">Manufacturer</a></th>
`;
  el.appendChild(header);

  for (const v of data) {
    const tr = document.createElement("tr");
    tr.innerHTML = `
 <td><a href="/conntrack?ip=${v.ip}">${v.ip}</a></td>
 <td>${v.name}</td>
 <td class="success">${fmtRate(v.in_rate)}</td>
 <td class="failed">${fmtRate(v.out_rate)}</td>
 <td>${v.hwaddr}</td>
 <td>${v.manufacturer}</td>
`;
    el.appendChild(tr);
  }

  const container = document.getElementById("hosts")!;
  container.textContent = "";
  container.appendChild(el);
};

updateData();

setInterval(async function () {
  if (document.getSelection()?.type !== "Range") {
    if (!document.hidden) {
      await updateData();
    }
  }
}, 900);

declare global {
  interface Window {
    app: any;
  }
}

window.app = this;
