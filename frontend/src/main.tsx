// React Aria's generated accessibility styles use the document CSP nonce.
const nonce = document.querySelector<HTMLScriptElement>("script[nonce]")?.nonce;
if (nonce && !document.querySelector('meta[property="csp-nonce"]')) {
  const meta = document.createElement("meta");
  meta.setAttribute("property", "csp-nonce");
  meta.nonce = nonce;
  document.head.append(meta);
}

if (import.meta.env.MODE === "sli-parity") {
  void import("./sli-v4/fixture-main");
} else {
  void import("./product-main");
}
