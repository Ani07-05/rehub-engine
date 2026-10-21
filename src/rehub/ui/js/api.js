const BASE = "/api";

async function request(method, path, body) {
  const headers = {};
  if (method !== "GET") headers["X-Rehub"] = "1";
  let payload;
  if (body !== undefined) {
    headers["Content-Type"] = "application/json";
    payload = JSON.stringify(body);
  }
  let res;
  try {
    res = await fetch(BASE + path, { method, headers, body: payload });
  } catch (err) {
    throw new Error("Cannot reach the ReHub server. Is it still running?");
  }
  let data = null;
  try {
    data = await res.json();
  } catch (err) {
    data = null;
  }
  if (!res.ok) throw new Error((data && data.error) || `Request failed (${res.status})`);
  return data;
}

export const api = {
  list: () => request("GET", "/investigations"),
  get: (id) => request("GET", `/investigations/${id}`),
  create: () => request("POST", "/investigations"),
  run: (id, plcIps) => request("POST", `/investigations/${id}/run`, { plc_ips: plcIps }),
  remove: (id) => request("DELETE", `/investigations/${id}`),
  lines: (id, sha, start, count) =>
    request("GET", `/investigations/${id}/evidence/${sha}/lines?start=${start}&count=${count}`),
  packets: (id, flowKey, limit) =>
    request("GET", `/investigations/${id}/flows/${encodeURIComponent(flowKey)}/packets?limit=${limit}`),
  downloadUrl: (id, sha) => `${BASE}/investigations/${id}/evidence/${sha}`,
  upload(id, file, onProgress) {
    return new Promise((resolve, reject) => {
      const xhr = new XMLHttpRequest();
      xhr.open("PUT", `${BASE}/investigations/${id}/files?name=${encodeURIComponent(file.name)}`);
      xhr.setRequestHeader("X-Rehub", "1");
      xhr.upload.onprogress = (e) => e.lengthComputable && onProgress(e.loaded / e.total);
      xhr.onerror = () => reject(new Error(`Upload of ${file.name} failed. Is the server running?`));
      xhr.onload = () => {
        let data = null;
        try {
          data = JSON.parse(xhr.responseText);
        } catch (err) {
          data = null;
        }
        if (xhr.status >= 200 && xhr.status < 300) resolve(data);
        else reject(new Error((data && data.error) || `Upload of ${file.name} failed (${xhr.status})`));
      };
      xhr.send(file);
    });
  },
};
