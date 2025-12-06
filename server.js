const express = require("express");
const path = require("path");
const cors = require("cors");
require("dotenv").config();
const fetch = require("node-fetch");

const app = express();
const PORT = process.env.PORT || 3000;

app.use(cors());
app.use(express.json());

// Отдаём статику из папки src
app.use(express.static(path.join(__dirname, "src")));

// Отдаём index.html на корень сайта
app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "src", "index.html"));
});

// Endpoint для проверки QR-ссылки через VirusTotal
app.post("/vt/scan", async (req, res) => {
  try {
    const { url } = req.body;
    if (!url) return res.status(400).json({ error: "URL отсутствует" });

    const apiKey = process.env.VIRUSTOTAL_API_KEY;
    if (!apiKey) return res.status(500).json({ error: "API ключ не настроен" });

    // Отправляем URL на проверку
    const vtResponse = await fetch("https://www.virustotal.com/api/v3/urls", {
      method: "POST",
      headers: { 
        "x-apikey": apiKey,
        "Content-Type": "application/x-www-form-urlencoded" 
      },
      body: `url=${encodeURIComponent(url)}`
    });

    const json = await vtResponse.json();
    const scanId = json.data.id;

    // Запрашиваем результат проверки
    const reportResponse = await fetch(
      `https://www.virustotal.com/api/v3/analyses/${scanId}`,
      { headers: { "x-apikey": apiKey } }
    );

    const reportJson = await reportResponse.json();
    const stats = reportJson.data.attributes.stats;

    res.json({
      harmless: stats.harmless,
      malicious: stats.malicious,
      suspicious: stats.suspicious,
      undetected: stats.undetected
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Ошибка проверки" });
  }
});

// Запуск сервера
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
