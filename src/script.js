document.getElementById("checkButton").addEventListener("click", async () => {
  const url = document.getElementById("urlInput").value;
  const res = await fetch("/vt/scan", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ url })
  });
  const data = await res.json();
  alert(`Malicious: ${data.malicious}, Harmless: ${data.harmless}`);
});
