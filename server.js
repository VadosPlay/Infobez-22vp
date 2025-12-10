const express = require("express");
const path = require("path");
const cors = require("cors");
require("dotenv").config();
const fetch = require("node-fetch");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Статика
app.use(express.static(path.join(__dirname, "src")));

// Главная страница
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "src", "index.html"));
});

// 🔥 VirusTotal proxy-endpoint
app.post("/vt/scan", async (req, res) => {
  try {
    const { url } = req.body;
    const apiKey = process.env.VIRUSTOTAL_API_KEY;

    if (!apiKey) {
      return res.json({ error: "API ключ не найден. Добавьте VIRUSTOTAL_API_KEY в .env" });
    }

    if (!url || !url.startsWith("http")) {
      return res.json({ error: "Некорректный URL" });
    }

    // 1️⃣ Отправляем на сканирование
    const scanRes = await fetch(
      "https://www.virustotal.com/api/v3/urls",
      {
        method: "POST",
        headers: {
          "Content-Type": "application/x-www-form-urlencoded",
          "x-apikey": apiKey
        },
        body: "url=" + encodeURIComponent(url)
      }
    );
    const scanData = await scanRes.json();

    if (!scanData.data || !scanData.data.id) {
      return res.json({ error: "VirusTotal не вернул ID" });
    }

    const analysisId = scanData.data.id;

    // 2️⃣ Ждём пока будет готов результат
    let tries = 0, resultData = null;
    while (tries < 8) {
      await new Promise(r => setTimeout(r, 1000)); // пауза 1 сек
      const res2 = await fetch(
        `https://www.virustotal.com/api/v3/analyses/${analysisId}`,
        { headers: { "x-apikey": apiKey } }
      );
      resultData = await res2.json();
      if (resultData.data?.attributes?.stats) break;
      tries++;
    }

    if (!resultData.data?.attributes?.stats) {
      return res.json({ error: "VT слишком долго отвечает, попробуйте позже" });
    }

    const stats = resultData.data.attributes.stats;

    return res.json({
      vtSummary: {
        engine_count: Object.values(stats).reduce((a, b) => a + b, 0),
        positives: stats.malicious || 0,
        suspicious: stats.suspicious || 0
      }
    });

  } catch (err) {
    console.error("VT ERROR:", err);
    res.json({ error: "Ошибка сервера: " + err.message });
  }
});

// Запуск сервера
app.listen(PORT, () => {
  console.log(`Server running http://localhost:${PORT}`);
});
