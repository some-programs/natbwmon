var __awaiter = (this && this.__awaiter) || function (thisArg, _arguments, P, generator) {
    function adopt(value) { return value instanceof P ? value : new P(function (resolve) { resolve(value); }); }
    return new (P || (P = Promise))(function (resolve, reject) {
        function fulfilled(value) { try { step(generator.next(value)); } catch (e) { reject(e); } }
        function rejected(value) { try { step(generator["throw"](value)); } catch (e) { reject(e); } }
        function step(result) { result.done ? resolve(result.value) : adopt(result.value).then(fulfilled, rejected); }
        step((generator = generator.apply(thisArg, _arguments || [])).next());
    });
};
define(["require", "exports"], function (require, exports) {
    "use strict";
    Object.defineProperty(exports, "__esModule", { value: true });
    exports.setOrderBy = void 0;
    var orderBy = "ip";
    const setOrderBy = (o) => {
        orderBy = o;
        updateData();
    };
    exports.setOrderBy = setOrderBy;
    const fmtRate = function (bytes, decimals = 2) {
        if (bytes < 0.01)
            return "";
        const k = 1024;
        const dm = decimals < 0 ? 0 : decimals;
        const sizes = ["B", "KB", "MB", "GB", "TB", "PB", "EB", "ZB", "YB"];
        const i = Math.floor(Math.log(bytes) / Math.log(k));
        const v = parseFloat((bytes / Math.pow(k, i)).toFixed(dm));
        return `${v} ${sizes[i]}/s`;
    };
    const hwaddrPrefix = (hwaddr) => {
        if (!hwaddr) {
            return "";
        }
        return hwaddr.substring(0, 8);
    };
    const updateData = () => __awaiter(void 0, void 0, void 0, function* () {
        const resp = yield fetch(`/v1/stats/?order_by=${orderBy}`);
        const data = yield resp.json();
        const container = document.getElementById("hosts");
        container.textContent = "";
        const header = document.createElement("tr");
        header.innerHTML = `
<th><button onclick="app.setOrderBy('ip')">IP</a></th>
<th><button onclick="app.setOrderBy('name')">Hostname</a></th>
<th><button onclick="app.setOrderBy('rate_in')">IN rate</a></th>
<th><button onclick="app.setOrderBy('rate_out')">OUT rate</a></th>
<th><button onclick="app.setOrderBy('hwaddr')">Hardware address</a></th>
`;
        container.appendChild(header);
        const rows = data.map((v) => {
            const tr = document.createElement("tr");
            tr.innerHTML = `
 <td><a href="/conntrack?ip=${v.ip}">${v.ip}</a></td>
 <td>${v.name}</td>
 <td class="success">${fmtRate(v.in_rate)}</td>
 <td class="failed">${fmtRate(v.out_rate)}</td>
 <td><a href="https://hwaddress.com/?q=${hwaddrPrefix(v.hwaddr)}">${v.hwaddr}</a></td>
`;
            container.appendChild(tr);
            return tr;
        });
    });
    const refreshRate = 800;
    updateData();
    const t = setInterval(function () {
        var _a;
        return __awaiter(this, void 0, void 0, function* () {
            if (((_a = document.getSelection()) === null || _a === void 0 ? void 0 : _a.type) !== "Range") {
                yield updateData();
            }
        });
    }, 900);
    window.app = this;
});
//# sourceMappingURL=data:application/json;base64,eyJ2ZXJzaW9uIjozLCJmaWxlIjoiY2xpZW50cy5qcyIsInNvdXJjZVJvb3QiOiIiLCJzb3VyY2VzIjpbIi4uL3RzL2NsaWVudHMudHMiXSwibmFtZXMiOltdLCJtYXBwaW5ncyI6Ijs7Ozs7Ozs7Ozs7OztJQVFBLElBQUksT0FBTyxHQUFHLElBQUksQ0FBQztJQUVaLE1BQU0sVUFBVSxHQUFHLENBQUMsQ0FBUyxFQUFFLEVBQUU7UUFDdEMsT0FBTyxHQUFHLENBQUMsQ0FBQztRQUNaLFVBQVUsRUFBRSxDQUFDO0lBQ2YsQ0FBQyxDQUFDO0lBSFcsUUFBQSxVQUFVLGNBR3JCO0lBRUYsTUFBTSxPQUFPLEdBQUcsVUFBVSxLQUFhLEVBQUUsUUFBUSxHQUFHLENBQUM7UUFDbkQsSUFBSSxLQUFLLEdBQUcsSUFBSTtZQUFFLE9BQU8sRUFBRSxDQUFDO1FBQzVCLE1BQU0sQ0FBQyxHQUFHLElBQUksQ0FBQztRQUNmLE1BQU0sRUFBRSxHQUFHLFFBQVEsR0FBRyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDLENBQUMsUUFBUSxDQUFDO1FBQ3ZDLE1BQU0sS0FBSyxHQUFHLENBQUMsR0FBRyxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxJQUFJLEVBQUUsSUFBSSxFQUFFLElBQUksRUFBRSxJQUFJLENBQUMsQ0FBQztRQUNwRSxNQUFNLENBQUMsR0FBRyxJQUFJLENBQUMsS0FBSyxDQUFDLElBQUksQ0FBQyxHQUFHLENBQUMsS0FBSyxDQUFDLEdBQUcsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQUMsQ0FBQyxDQUFDO1FBQ3BELE1BQU0sQ0FBQyxHQUFHLFVBQVUsQ0FBQyxDQUFDLEtBQUssR0FBRyxJQUFJLENBQUMsR0FBRyxDQUFDLENBQUMsRUFBRSxDQUFDLENBQUMsQ0FBQyxDQUFDLE9BQU8sQ0FBQyxFQUFFLENBQUMsQ0FBQyxDQUFDO1FBQzNELE9BQU8sR0FBRyxDQUFDLElBQUksS0FBSyxDQUFDLENBQUMsQ0FBQyxJQUFJLENBQUM7SUFDOUIsQ0FBQyxDQUFDO0lBRUYsTUFBTSxZQUFZLEdBQUcsQ0FBQyxNQUFjLEVBQUUsRUFBRTtRQUN0QyxJQUFJLENBQUMsTUFBTSxFQUFFO1lBQ1gsT0FBTyxFQUFFLENBQUM7U0FDWDtRQUNELE9BQU8sTUFBTSxDQUFDLFNBQVMsQ0FBQyxDQUFDLEVBQUUsQ0FBQyxDQUFDLENBQUM7SUFDaEMsQ0FBQyxDQUFDO0lBRUYsTUFBTSxVQUFVLEdBQUcsR0FBUyxFQUFFO1FBQzVCLE1BQU0sSUFBSSxHQUFHLE1BQU0sS0FBSyxDQUFDLHVCQUF1QixPQUFPLEVBQUUsQ0FBQyxDQUFDO1FBQzNELE1BQU0sSUFBSSxHQUFHLE1BQU0sSUFBSSxDQUFDLElBQUksRUFBRSxDQUFDO1FBQy9CLE1BQU0sU0FBUyxHQUFHLFFBQVEsQ0FBQyxjQUFjLENBQUMsT0FBTyxDQUFFLENBQUM7UUFDcEQsU0FBUyxDQUFDLFdBQVcsR0FBRyxFQUFFLENBQUM7UUFDM0IsTUFBTSxNQUFNLEdBQUcsUUFBUSxDQUFDLGFBQWEsQ0FBQyxJQUFJLENBQUMsQ0FBQztRQUM1QyxNQUFNLENBQUMsU0FBUyxHQUFHOzs7Ozs7Q0FNcEIsQ0FBQztRQUNBLFNBQVMsQ0FBQyxXQUFXLENBQUMsTUFBTSxDQUFDLENBQUM7UUFFOUIsTUFBTSxJQUFJLEdBQUcsSUFBSSxDQUFDLEdBQUcsQ0FBQyxDQUFDLENBQU0sRUFBRSxFQUFFO1lBQy9CLE1BQU0sRUFBRSxHQUFHLFFBQVEsQ0FBQyxhQUFhLENBQUMsSUFBSSxDQUFDLENBQUM7WUFDeEMsRUFBRSxDQUFDLFNBQVMsR0FBRzs4QkFDVyxDQUFDLENBQUMsRUFBRSxLQUFLLENBQUMsQ0FBQyxFQUFFO09BQ3BDLENBQUMsQ0FBQyxJQUFJO3VCQUNVLE9BQU8sQ0FBQyxDQUFDLENBQUMsT0FBTyxDQUFDO3NCQUNuQixPQUFPLENBQUMsQ0FBQyxDQUFDLFFBQVEsQ0FBQzt5Q0FDQSxZQUFZLENBQUMsQ0FBQyxDQUFDLE1BQU0sQ0FBQyxLQUN6RCxDQUFDLENBQUMsTUFDSjtDQUNILENBQUM7WUFFRSxTQUFTLENBQUMsV0FBVyxDQUFDLEVBQUUsQ0FBQyxDQUFDO1lBQzFCLE9BQU8sRUFBRSxDQUFDO1FBQ1osQ0FBQyxDQUFDLENBQUM7SUFDTCxDQUFDLENBQUEsQ0FBQztJQUVGLE1BQU0sV0FBVyxHQUFHLEdBQUcsQ0FBQztJQUV4QixVQUFVLEVBQUUsQ0FBQztJQUViLE1BQU0sQ0FBQyxHQUFHLFdBQVcsQ0FBQzs7O1lBQ3BCLElBQUksT0FBQSxRQUFRLENBQUMsWUFBWSxFQUFFLDBDQUFFLElBQUksTUFBSyxPQUFPLEVBQUU7Z0JBQzdDLE1BQU0sVUFBVSxFQUFFLENBQUM7YUFDcEI7O0tBQ0YsRUFBRSxHQUFHLENBQUMsQ0FBQztJQVFSLE1BQU0sQ0FBQyxHQUFHLEdBQUcsSUFBSSxDQUFDIn0=